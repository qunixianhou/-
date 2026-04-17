from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser
from email.utils import format_datetime, make_msgid
from typing import Dict, List, Optional, Sequence, Tuple, Union

from .types import DEFAULT_BOUND_PUBLIC_HEADER_KEYS, EmailContent, TransportParseResult


@dataclass(frozen=True)
class TransportProfileSpec:
    name: str
    max_line_length: int = 78
    line_ending: str = "CRLF"
    rewrite_from: Optional[str] = None
    rewrite_date: bool = False
    rewrite_message_id: bool = False
    strip_extra_headers: bool = False
    drop_headers: Tuple[str, ...] = ()
    text_cte: Optional[str] = None
    attachment_cte: Optional[str] = None
    sort_extra_headers: bool = False


TransportProfile = Union[str, TransportProfileSpec]
TransportMutationProfile = TransportProfileSpec
TransportMutationProfileSpec = TransportProfileSpec


@dataclass
class TransportMutationReport:
    profile_name: str
    rewritten_fields: List[str] = field(default_factory=list)
    dropped_headers: List[str] = field(default_factory=list)
    stripped_extra_headers: List[str] = field(default_factory=list)
    line_ending: str = "CRLF"
    max_line_length: int = 78
    text_cte: Optional[str] = None
    attachment_cte: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    original_size: int = 0
    transported_size: int = 0


@dataclass
class TransportSurvivability:
    transported_raw: bytes
    parsed: Optional[TransportParseResult]
    report: TransportMutationReport
    protected_equivalent: bool
    payload_equivalent: bool
    public_headers_preserved: Dict[str, bool]
    custom_headers_preserved: Dict[str, bool]
    binding_fields: List[str]
    binding_preserved: bool
    parse_error: Optional[str] = None

    @property
    def mutation_report(self) -> TransportMutationReport:
        return self.report

    @property
    def public_header_survival(self) -> Dict[str, bool]:
        return self.public_headers_preserved

    @property
    def extra_header_survival(self) -> Dict[str, bool]:
        return self.custom_headers_preserved


TransportRoundTripResult = TransportSurvivability


IDENTITY_PROFILE = TransportProfileSpec(name="identity")
REFOLDED_PROFILE = TransportProfileSpec(name="refolded", max_line_length=52, sort_extra_headers=True)
QP_TEXT_PROFILE = TransportProfileSpec(name="quoted-printable", text_cte="quoted-printable")
ATTACHMENT_BASE64_PROFILE = TransportProfileSpec(name="attachment-base64", attachment_cte="base64")
REWRITE_PROFILE = TransportProfileSpec(
    name="provider-rewrite",
    max_line_length=72,
    rewrite_date=True,
    rewrite_message_id=True,
    strip_extra_headers=True,
)
AGGRESSIVE_GATEWAY_PROFILE = TransportProfileSpec(
    name="aggressive-gateway",
    max_line_length=72,
    rewrite_from="gateway@example.transport",
    rewrite_date=True,
    rewrite_message_id=True,
    strip_extra_headers=True,
    text_cte="quoted-printable",
    attachment_cte="base64",
    sort_extra_headers=True,
)

STANDARD_SURVIVAL_PROFILES: Dict[str, TransportProfileSpec] = {
    profile.name: profile
    for profile in (
        IDENTITY_PROFILE,
        REFOLDED_PROFILE,
        QP_TEXT_PROFILE,
        ATTACHMENT_BASE64_PROFILE,
        REWRITE_PROFILE,
        AGGRESSIVE_GATEWAY_PROFILE,
    )
}
STANDARD_TRANSPORT_PROFILES = STANDARD_SURVIVAL_PROFILES


def _utc_rfc2822_now() -> str:
    return format_datetime(datetime.now(tz=timezone.utc))


def _resolve_profile(profile: TransportProfile) -> TransportProfileSpec:
    if isinstance(profile, TransportProfileSpec):
        return profile
    if profile not in STANDARD_SURVIVAL_PROFILES:
        raise KeyError(f"unknown transport profile: {profile}")
    return STANDARD_SURVIVAL_PROFILES[profile]


def to_submission_bytes(mail: EmailContent) -> bytes:
    return mail.to_submission_bytes() if hasattr(mail, "to_submission_bytes") else mail.to_rfc822_bytes()


def from_transport_bytes(raw: bytes) -> TransportParseResult:
    return EmailContent.from_transport_or_bytes(raw)


def _drop_requested_headers(mail: EmailContent, report: TransportMutationReport, names: Sequence[str]) -> None:
    wanted = {name.lower() for name in names}
    if not wanted:
        return
    for header_name in list(mail.extra_headers.keys()):
        if header_name.lower() in wanted:
            report.dropped_headers.append(header_name)
            del mail.extra_headers[header_name]


def mutate_via_transport(raw: bytes, profile: TransportProfile) -> tuple[bytes, TransportMutationReport]:
    chosen = _resolve_profile(profile)
    report = TransportMutationReport(
        profile_name=chosen.name,
        line_ending=chosen.line_ending,
        max_line_length=chosen.max_line_length,
        text_cte=chosen.text_cte,
        attachment_cte=chosen.attachment_cte,
        original_size=len(raw),
    )
    mail = EmailContent.from_rfc822_bytes(raw, preserve_extra_headers=True)

    if chosen.rewrite_from is not None and mail.mail_from != chosen.rewrite_from:
        mail.mail_from = chosen.rewrite_from
        report.rewritten_fields.append("mail_from")
    if chosen.rewrite_date:
        mail.date = _utc_rfc2822_now()
        report.rewritten_fields.append("date")
    if chosen.rewrite_message_id:
        mail.message_id = make_msgid(domain="transport.local")
        report.rewritten_fields.append("message_id")

    _drop_requested_headers(mail, report, chosen.drop_headers)
    if chosen.strip_extra_headers and mail.extra_headers:
        report.stripped_extra_headers.extend(sorted(mail.extra_headers.keys()))
        mail.extra_headers = {}

    if chosen.max_line_length != 78:
        report.notes.append(f"header-refold:max_line_length={chosen.max_line_length}")
    if chosen.text_cte is not None:
        report.notes.append(f"text-cte={chosen.text_cte}")
    if chosen.attachment_cte is not None:
        report.notes.append(f"attachment-cte={chosen.attachment_cte}")

    transported = mail.to_rfc822_bytes(
        text_cte=chosen.text_cte,
        html_cte=chosen.text_cte,
        attachment_cte=chosen.attachment_cte,
        max_line_length=chosen.max_line_length,
        line_ending=chosen.line_ending,
        sort_extra_headers=chosen.sort_extra_headers,
    )
    report.transported_size = len(transported)
    return transported, report


def _compare_public_headers(original: EmailContent, parsed: EmailContent) -> Dict[str, bool]:
    return {
        "mail_from": original.mail_from == parsed.mail_from,
        "rcpt_to": sorted(original.to) == sorted(parsed.to),
        "cc": sorted(original.cc) == sorted(parsed.cc),
        "message_id": original.message_id == parsed.message_id,
        "date": original.date == parsed.date,
    }


def _compare_extra_headers(original: EmailContent, parsed: EmailContent) -> Dict[str, bool]:
    keys = sorted(set(original.extra_headers) | set(parsed.extra_headers))
    return {name: original.extra_headers.get(name) == parsed.extra_headers.get(name) for name in keys}


def binding_survivability(
    original: EmailContent,
    transported_raw: bytes,
    report: Optional[TransportMutationReport] = None,
    *,
    binding_fields: Sequence[str] = DEFAULT_BOUND_PUBLIC_HEADER_KEYS,
) -> TransportSurvivability:
    try:
        parsed = from_transport_bytes(transported_raw)
    except Exception as exc:
        return TransportSurvivability(
            transported_raw=transported_raw,
            parsed=None,
            report=report or TransportMutationReport(profile_name="observed-only"),
            protected_equivalent=False,
            payload_equivalent=False,
            public_headers_preserved={field: False for field in DEFAULT_BOUND_PUBLIC_HEADER_KEYS},
            custom_headers_preserved={},
            binding_fields=list(binding_fields),
            binding_preserved=False,
            parse_error=str(exc),
        )

    public_headers_preserved = _compare_public_headers(original, parsed.mail)
    custom_headers_preserved = _compare_extra_headers(original, parsed.mail)
    payload_equivalent = original.logical_payload_equivalent(parsed.mail)
    binding_preserved = payload_equivalent and all(public_headers_preserved.get(field, False) for field in binding_fields)
    return TransportSurvivability(
        transported_raw=transported_raw,
        parsed=parsed,
        report=report or TransportMutationReport(profile_name="observed-only"),
        protected_equivalent=payload_equivalent,
        payload_equivalent=payload_equivalent,
        public_headers_preserved=public_headers_preserved,
        custom_headers_preserved=custom_headers_preserved,
        binding_fields=list(binding_fields),
        binding_preserved=binding_preserved,
    )


def simulate_transport(
    mail: EmailContent,
    profile: TransportProfile,
    *,
    binding_fields: Sequence[str] = DEFAULT_BOUND_PUBLIC_HEADER_KEYS,
) -> TransportSurvivability:
    transported, report = mutate_via_transport(to_submission_bytes(mail), profile)
    return binding_survivability(mail, transported, report, binding_fields=binding_fields)


def analyze_transport_survival(
    raw: Union[bytes, EmailContent],
    profile: TransportProfile = AGGRESSIVE_GATEWAY_PROFILE,
    *,
    binding_fields: Sequence[str] = DEFAULT_BOUND_PUBLIC_HEADER_KEYS,
) -> TransportSurvivability:
    if isinstance(raw, EmailContent):
        original = raw
        submission = to_submission_bytes(raw)
    else:
        original = EmailContent.from_rfc822_bytes(raw, preserve_extra_headers=True)
        submission = raw
    transported, report = mutate_via_transport(submission, profile)
    return binding_survivability(original, transported, report, binding_fields=binding_fields)


analyze_transport_survivability = analyze_transport_survival
evaluate_transport_survivability = analyze_transport_survival
analyze_transport_round_trip = analyze_transport_survival
mutate_transport_bytes = mutate_via_transport
