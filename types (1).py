from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, format_datetime, make_msgid
from typing import Any, Dict, List, Mapping, Optional


DEFAULT_BOUND_PUBLIC_HEADER_KEYS = ("mail_from", "rcpt_to", "cc", "message_id", "date")


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for signing and hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def utc_rfc2822_now() -> str:
    return format_datetime(datetime.now(tz=timezone.utc))


@dataclass(frozen=True)
class DevicePub:
    pk_sig: bytes
    pk_kem: bytes

    def to_json(self) -> Dict[str, str]:
        return {"pk_sig": b64e(self.pk_sig), "pk_kem": b64e(self.pk_kem)}

    @staticmethod
    def from_json(d: Mapping[str, str]) -> "DevicePub":
        return DevicePub(pk_sig=b64d(d["pk_sig"]), pk_kem=b64d(d["pk_kem"]))


@dataclass
class MailAttachment:
    filename: str
    content_type: str
    data: bytes
    disposition: str = "attachment"
    content_id: Optional[str] = None

    def clone(self) -> "MailAttachment":
        return MailAttachment(
            filename=self.filename,
            content_type=self.content_type,
            data=bytes(self.data),
            disposition=self.disposition,
            content_id=self.content_id,
        )

    def to_json(self) -> Dict[str, Any]:
        return {
            "filename": self.filename,
            "content_type": self.content_type,
            "data": b64e(self.data),
            "disposition": self.disposition,
            "content_id": self.content_id,
        }

    @staticmethod
    def from_json(d: Mapping[str, Any]) -> "MailAttachment":
        return MailAttachment(
            filename=str(d["filename"]),
            content_type=str(d["content_type"]),
            data=b64d(str(d["data"])),
            disposition=str(d.get("disposition", "attachment")),
            content_id=d.get("content_id"),
        )


@dataclass
class EmailContent:
    """Protected mail-shaped payload carried inside the encrypted MessageBlob.

    The object is serialized to RFC 5322-style bytes locally, but we also expose
    transport-oriented parsing helpers so the prototype can model how a protected
    mail object survives (or fails to survive) plausible transport rewriting.
    """

    mail_from: str
    to: List[str]
    subject: str
    text_body: str
    message_id: str = field(default_factory=lambda: make_msgid(domain="anchormail.local"))
    date: str = field(default_factory=utc_rfc2822_now)
    cc: List[str] = field(default_factory=list)
    in_reply_to: Optional[str] = None
    references: List[str] = field(default_factory=list)
    html_body: Optional[str] = None
    attachments: List[MailAttachment] = field(default_factory=list)
    extra_headers: Dict[str, str] = field(default_factory=dict)

    @staticmethod
    def simple(mail_from: str, to: List[str], subject: str, text_body: str) -> "EmailContent":
        return EmailContent(mail_from=mail_from, to=list(to), subject=subject, text_body=text_body)

    def clone(self) -> "EmailContent":
        return EmailContent(
            mail_from=self.mail_from,
            to=list(self.to),
            subject=self.subject,
            text_body=self.text_body,
            message_id=self.message_id,
            date=self.date,
            cc=list(self.cc),
            in_reply_to=self.in_reply_to,
            references=list(self.references),
            html_body=self.html_body,
            attachments=[att.clone() for att in self.attachments],
            extra_headers=dict(self.extra_headers),
        )

    def public_header_obj(self) -> Dict[str, Any]:
        return {
            "mail_from": self.mail_from,
            "rcpt_to": list(self.to),
            "cc": list(self.cc),
            "message_id": self.message_id,
            "date": self.date,
        }

    def protected_payload_obj(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "text_body": self.text_body,
            "html_body": self.html_body,
            "attachments": [a.to_json() for a in self.attachments],
            "in_reply_to": self.in_reply_to,
            "references": list(self.references),
        }

    def canonical_obj(self) -> Dict[str, Any]:
        return {
            "mail_from": self.mail_from,
            "to": list(self.to),
            "cc": list(self.cc),
            "subject": self.subject,
            "text_body": self.text_body,
            "html_body": self.html_body,
            "attachments": [a.to_json() for a in self.attachments],
            "message_id": self.message_id,
            "date": self.date,
            "in_reply_to": self.in_reply_to,
            "references": list(self.references),
            "extra_headers": dict(self.extra_headers),
        }

    @staticmethod
    def _normalize_body_text(value: Optional[str]) -> Optional[str]:
        if value is None:
            return None
        return value.replace("\r\n", "\n").rstrip("\n")

    def logical_payload_equivalent(self, other: "EmailContent") -> bool:
        return {
            "subject": self.subject,
            "text_body": self._normalize_body_text(self.text_body),
            "html_body": self._normalize_body_text(self.html_body),
            "attachments": [a.to_json() for a in self.attachments],
            "in_reply_to": self.in_reply_to,
            "references": list(self.references),
        } == {
            "subject": other.subject,
            "text_body": self._normalize_body_text(other.text_body),
            "html_body": self._normalize_body_text(other.html_body),
            "attachments": [a.to_json() for a in other.attachments],
            "in_reply_to": other.in_reply_to,
            "references": list(other.references),
        }

    def to_email_message(
        self,
        *,
        text_cte: Optional[str] = None,
        html_cte: Optional[str] = None,
        attachment_cte: Optional[str] = None,
        email_policy: Any = policy.SMTP,
        sort_extra_headers: bool = False,
    ) -> EmailMessage:
        msg = EmailMessage(policy=email_policy)
        msg["Message-ID"] = self.message_id
        msg["Date"] = self.date
        msg["From"] = self.mail_from
        msg["To"] = ", ".join(self.to)
        if self.cc:
            msg["Cc"] = ", ".join(self.cc)
        if self.in_reply_to:
            msg["In-Reply-To"] = self.in_reply_to
        if self.references:
            msg["References"] = " ".join(self.references)
        msg["Subject"] = self.subject

        header_items = self.extra_headers.items()
        if sort_extra_headers:
            header_items = sorted(header_items)
        for k, v in header_items:
            if k not in msg:
                msg[k] = v

        has_attachments = bool(self.attachments)
        if self.html_body is None and not has_attachments:
            kwargs: Dict[str, Any] = {}
            if text_cte is not None:
                kwargs["cte"] = text_cte
            msg.set_content(self.text_body, **kwargs)
            return msg

        text_kwargs: Dict[str, Any] = {}
        if text_cte is not None:
            text_kwargs["cte"] = text_cte
        msg.set_content(self.text_body, **text_kwargs)
        if self.html_body is not None:
            html_kwargs: Dict[str, Any] = {}
            if html_cte is not None:
                html_kwargs["cte"] = html_cte
            msg.add_alternative(self.html_body, subtype="html", **html_kwargs)
        for att in self.attachments:
            maintype, subtype = att.content_type.split("/", 1)
            att_kwargs: Dict[str, Any] = {
                "maintype": maintype,
                "subtype": subtype,
                "filename": att.filename,
                "disposition": att.disposition,
                "cid": att.content_id,
            }
            if attachment_cte is not None:
                att_kwargs["cte"] = attachment_cte
            msg.add_attachment(att.data, **att_kwargs)
        return msg

    def to_rfc822_bytes(
        self,
        *,
        text_cte: Optional[str] = None,
        html_cte: Optional[str] = None,
        attachment_cte: Optional[str] = None,
        max_line_length: int = 78,
        line_ending: str = "CRLF",
        sort_extra_headers: bool = False,
    ) -> bytes:
        line_sep = "\r\n" if line_ending.upper() == "CRLF" else "\n"
        email_policy = policy.SMTP.clone(max_line_length=max_line_length, linesep=line_sep)
        return self.to_email_message(
            text_cte=text_cte,
            html_cte=html_cte,
            attachment_cte=attachment_cte,
            email_policy=email_policy,
            sort_extra_headers=sort_extra_headers,
        ).as_bytes(policy=email_policy)

    def to_submission_bytes(self) -> bytes:
        return self.to_rfc822_bytes()

    @staticmethod
    def from_rfc822_bytes(raw: bytes, preserve_extra_headers: bool = True) -> "EmailContent":
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        text_body = ""
        html_body: Optional[str] = None
        attachments: List[MailAttachment] = []

        if parsed.is_multipart():
            for part in parsed.walk():
                if part.is_multipart():
                    continue
                content_type = part.get_content_type()
                disposition = part.get_content_disposition()
                if disposition == "attachment":
                    payload = part.get_payload(decode=True) or b""
                    attachments.append(
                        MailAttachment(
                            filename=part.get_filename() or "attachment.bin",
                            content_type=content_type,
                            data=payload,
                            disposition=disposition or "attachment",
                            content_id=part.get("Content-ID"),
                        )
                    )
                    continue
                if content_type == "text/plain" and disposition != "attachment":
                    text_body = part.get_content()
                elif content_type == "text/html" and disposition != "attachment":
                    html_body = part.get_content()
        else:
            text_body = parsed.get_content()

        refs_raw = parsed.get("References", "")
        references = [x for x in refs_raw.split() if x]
        reserved = {
            "message-id",
            "date",
            "from",
            "to",
            "cc",
            "subject",
            "in-reply-to",
            "references",
            "mime-version",
            "content-type",
            "content-transfer-encoding",
            "content-disposition",
            "content-id",
        }
        extra_headers: Dict[str, str] = {}
        if preserve_extra_headers:
            for name, value in parsed.raw_items():
                if name.lower() not in reserved:
                    extra_headers.setdefault(name, str(value))

        return EmailContent(
            mail_from=parsed.get("From", ""),
            to=[addr for _, addr in getaddresses([parsed.get("To", "")])],
            cc=[addr for _, addr in getaddresses([parsed.get("Cc", "")]) if addr],
            subject=parsed.get("Subject", ""),
            text_body=text_body,
            html_body=html_body,
            attachments=attachments,
            message_id=parsed.get("Message-ID", ""),
            date=parsed.get("Date", ""),
            in_reply_to=parsed.get("In-Reply-To"),
            references=references,
            extra_headers=extra_headers,
        )

    @staticmethod
    def from_transport_or_bytes(raw: bytes) -> "TransportParseResult":
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        header_order = [name for name, _ in parsed.raw_items()]
        seen: Dict[str, int] = {}
        duplicates: List[str] = []
        observed: Dict[str, str] = {}
        for name, value in parsed.raw_items():
            lower = name.lower()
            seen[lower] = seen.get(lower, 0) + 1
            if seen[lower] == 2:
                duplicates.append(name)
            observed.setdefault(name, str(value))
        return TransportParseResult(
            mail=EmailContent.from_rfc822_bytes(raw, preserve_extra_headers=True),
            observed_headers=observed,
            raw_header_order=header_order,
            duplicate_header_names=duplicates,
            raw_size=len(raw),
            line_ending=_detect_line_ending(raw),
        )


@dataclass
class StateBlob:
    principal: str
    kind: str  # GENESIS/PROGRESS/JOIN/REMOVE/MERGE/RESET
    seq: int
    parents: List[str]
    epoch: int
    manifest: Dict[str, DevicePub]
    ek: bytes
    wraps: Dict[str, bytes]
    signer: str
    signature: bytes

    def body_obj(self) -> Dict[str, Any]:
        return {
            "principal": self.principal,
            "kind": self.kind,
            "seq": self.seq,
            "parents": list(self.parents),
            "epoch": self.epoch,
            "manifest": {did: pub.to_json() for did, pub in self.manifest.items()},
            "ek": b64e(self.ek),
            "wraps": {did: b64e(w) for did, w in self.wraps.items()},
            "signer": self.signer,
        }

    def signed_bytes(self) -> bytes:
        return canonical_json(self.body_obj())

    def to_obj(self) -> Dict[str, Any]:
        o = self.body_obj()
        o["signature"] = b64e(self.signature)
        return o

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_obj())

    @staticmethod
    def from_bytes(b: bytes) -> "StateBlob":
        o = json.loads(b.decode("utf-8"))
        manifest = {did: DevicePub.from_json(pub) for did, pub in o["manifest"].items()}
        wraps = {did: b64d(w) for did, w in o["wraps"].items()}
        return StateBlob(
            principal=o["principal"],
            kind=o["kind"],
            seq=int(o["seq"]),
            parents=list(o["parents"]),
            epoch=int(o["epoch"]),
            manifest=manifest,
            ek=b64d(o["ek"]),
            wraps=wraps,
            signer=o["signer"],
            signature=b64d(o["signature"]),
        )

    def obj_id(self) -> str:
        return sha256_hex(self.to_bytes())


@dataclass
class MessageBlob:
    epoch: int
    hdr: Dict[str, Any]
    ct_e: bytes
    nonce: bytes
    ciphertext: bytes
    signer: str
    signature: bytes

    def aad_obj(self) -> Dict[str, Any]:
        return {
            "epoch": self.epoch,
            "hdr": self.hdr,
            "ct_e": b64e(self.ct_e),
        }

    def aad_bytes(self) -> bytes:
        return canonical_json(self.aad_obj())

    def signed_obj(self) -> Dict[str, Any]:
        return {
            "epoch": self.epoch,
            "hdr": self.hdr,
            "ct_e": b64e(self.ct_e),
            "nonce": b64e(self.nonce),
            "ciphertext": b64e(self.ciphertext),
            "signer": self.signer,
        }

    def signed_bytes(self) -> bytes:
        return canonical_json(self.signed_obj())

    def to_obj(self) -> Dict[str, Any]:
        o = self.signed_obj()
        o["signature"] = b64e(self.signature)
        return o

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_obj())

    @staticmethod
    def from_bytes(b: bytes) -> "MessageBlob":
        o = json.loads(b.decode("utf-8"))
        return MessageBlob(
            epoch=int(o["epoch"]),
            hdr=o["hdr"],
            ct_e=b64d(o["ct_e"]),
            nonce=b64d(o["nonce"]),
            ciphertext=b64d(o["ciphertext"]),
            signer=o["signer"],
            signature=b64d(o["signature"]),
        )

    def obj_id(self) -> str:
        return sha256_hex(self.to_bytes())


@dataclass
class DelegationPackage:
    principal: str
    exporter_device: str
    exporter_auth_ref: str
    target_device: str
    target_pk_kem: bytes
    state_bundle: Dict[str, bytes]
    state_wraps: Dict[str, bytes]
    remote_view_hints: Dict[str, str]
    signature: bytes

    def body_obj(self) -> Dict[str, Any]:
        return {
            "principal": self.principal,
            "exporter_device": self.exporter_device,
            "exporter_auth_ref": self.exporter_auth_ref,
            "target_device": self.target_device,
            "target_pk_kem": b64e(self.target_pk_kem),
            "state_bundle": {sid: b64e(raw) for sid, raw in self.state_bundle.items()},
            "state_wraps": {sid: b64e(w) for sid, w in self.state_wraps.items()},
            "remote_view_hints": dict(self.remote_view_hints),
        }

    def signed_bytes(self) -> bytes:
        return canonical_json(self.body_obj())

    def to_obj(self) -> Dict[str, Any]:
        o = self.body_obj()
        o["signature"] = b64e(self.signature)
        return o

    def to_bytes(self) -> bytes:
        return canonical_json(self.to_obj())

    @staticmethod
    def from_bytes(b: bytes) -> "DelegationPackage":
        o = json.loads(b.decode("utf-8"))
        return DelegationPackage(
            principal=o["principal"],
            exporter_device=o["exporter_device"],
            exporter_auth_ref=o["exporter_auth_ref"],
            target_device=o["target_device"],
            target_pk_kem=b64d(o["target_pk_kem"]),
            state_bundle={sid: b64d(raw) for sid, raw in o["state_bundle"].items()},
            state_wraps={sid: b64d(w) for sid, w in o["state_wraps"].items()},
            remote_view_hints=dict(o.get("remote_view_hints", {})),
            signature=b64d(o["signature"]),
        )


@dataclass
class ForkEvidence:
    subject: str
    ref_id: str
    ref_role: str
    reason: str


@dataclass
class GapEvidence:
    stream_id: str
    accepted_ctr: int
    contiguous_high_before: int
    missing: List[int]


@dataclass
class ReceiveResult:
    decision: str
    plaintext: Optional[bytes]
    mail: Optional[EmailContent]
    alerts: List[str]
    reasons: List[str]
    fork_evidence: Optional[ForkEvidence] = None
    gap_evidence: Optional[GapEvidence] = None
    mb_id: Optional[str] = None


@dataclass
class TransportParseResult:
    mail: EmailContent
    observed_headers: Dict[str, str]
    raw_header_order: List[str]
    duplicate_header_names: List[str]
    raw_size: int
    line_ending: str


def _detect_line_ending(raw: bytes) -> str:
    has_crlf = b"\r\n" in raw
    has_lf = b"\n" in raw.replace(b"\r\n", b"")
    if has_crlf and has_lf:
        return "MIXED"
    if has_crlf:
        return "CRLF"
    if has_lf:
        return "LF"
    return "NONE"
