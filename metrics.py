from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from .types import DelegationPackage, EmailContent, MessageBlob, StateBlob, canonical_json


@dataclass(frozen=True)
class StateBlobMetrics:
    serialized_bytes: int
    authenticated_body_bytes: int
    parent_count: int
    manifest_size: int
    wrap_count: int


@dataclass(frozen=True)
class MessageBlobMetrics:
    serialized_bytes: int
    authenticated_body_bytes: int
    header_bytes: int
    ciphertext_bytes: int
    protected_mail_bytes: Optional[int]
    logical_payload_bytes: Optional[int]
    attachment_count: Optional[int]


@dataclass(frozen=True)
class DelegationPackageMetrics:
    serialized_bytes: int
    authenticated_body_bytes: int
    state_bundle_count: int
    state_bundle_bytes: int
    state_wrap_count: int
    hint_count: int


@dataclass(frozen=True)
class DeviceGrowthSnapshot:
    principal: str
    visible_subjects: int
    self_state_count: int
    self_valid_state_count: int
    self_head_count: int
    selected_head: Optional[str]
    current_manifest_size: int
    cached_state_keys: int
    outbound_streams: int
    inbound_streams: int
    infra_stats: Optional[Dict[str, int]] = None


@dataclass(frozen=True)
class TransportSizeMetrics:
    logical_payload_bytes: int
    public_header_bytes: int
    submission_bytes: int
    transport_bytes: Optional[int]
    overhead_bytes: Optional[int]
    overhead_ratio: Optional[float]
    binding_preserved: Optional[bool]


def measure_state_blob(sb: StateBlob) -> StateBlobMetrics:
    return StateBlobMetrics(
        serialized_bytes=len(sb.to_bytes()),
        authenticated_body_bytes=len(sb.signed_bytes()),
        parent_count=len(sb.parents),
        manifest_size=len(sb.manifest),
        wrap_count=len(sb.wraps),
    )


def measure_message_blob(mb: MessageBlob, protected_mail: EmailContent | bytes | None = None) -> MessageBlobMetrics:
    if isinstance(protected_mail, EmailContent):
        protected_mail_bytes = len(protected_mail.to_rfc822_bytes())
        logical_payload_bytes = len(canonical_json(protected_mail.protected_payload_obj()))
        attachment_count = len(protected_mail.attachments)
    elif isinstance(protected_mail, bytes):
        protected_mail_bytes = len(protected_mail)
        logical_payload_bytes = None
        attachment_count = None
    else:
        protected_mail_bytes = None
        logical_payload_bytes = None
        attachment_count = None
    return MessageBlobMetrics(
        serialized_bytes=len(mb.to_bytes()),
        authenticated_body_bytes=len(mb.signed_bytes()),
        header_bytes=len(canonical_json(mb.hdr)),
        ciphertext_bytes=len(mb.ciphertext),
        protected_mail_bytes=protected_mail_bytes,
        logical_payload_bytes=logical_payload_bytes,
        attachment_count=attachment_count,
    )


def measure_delegation_package(pkg: DelegationPackage) -> DelegationPackageMetrics:
    return DelegationPackageMetrics(
        serialized_bytes=len(pkg.to_bytes()),
        authenticated_body_bytes=len(pkg.signed_bytes()),
        state_bundle_count=len(pkg.state_bundle),
        state_bundle_bytes=sum(len(raw) for raw in pkg.state_bundle.values()),
        state_wrap_count=len(pkg.state_wraps),
        hint_count=len(pkg.remote_view_hints),
    )


def snapshot_device_growth(device: Any) -> DeviceGrowthSnapshot:
    self_view = device.views.get(device.principal)
    infra_stats = device.infra.stats_snapshot().__dict__ if hasattr(device.infra, "stats_snapshot") else None
    if self_view is None:
        return DeviceGrowthSnapshot(
            principal=device.principal,
            visible_subjects=len(device.views),
            self_state_count=0,
            self_valid_state_count=0,
            self_head_count=0,
            selected_head=None,
            current_manifest_size=0,
            cached_state_keys=len(device.state_dk_cache),
            outbound_streams=len(device.send_ctr),
            inbound_streams=len(device.recv_progress),
            infra_stats=infra_stats,
        )
    head = self_view.head()
    return DeviceGrowthSnapshot(
        principal=device.principal,
        visible_subjects=len(device.views),
        self_state_count=len(self_view.sbs),
        self_valid_state_count=len(self_view.valid),
        self_head_count=len(self_view.heads),
        selected_head=self_view.selected_head,
        current_manifest_size=len(head.manifest) if head is not None else 0,
        cached_state_keys=len(device.state_dk_cache),
        outbound_streams=len(device.send_ctr),
        inbound_streams=len(device.recv_progress),
        infra_stats=infra_stats,
    )


def measure_transport_growth(mail: EmailContent, survivability: Any | None = None) -> TransportSizeMetrics:
    submission_bytes = len(mail.to_rfc822_bytes())
    transport_bytes: Optional[int] = None
    overhead_bytes: Optional[int] = None
    overhead_ratio: Optional[float] = None
    binding_preserved: Optional[bool] = None
    if survivability is not None:
        transport_bytes = len(getattr(survivability, "transported_raw", b""))
        if transport_bytes > 0:
            overhead_bytes = transport_bytes - submission_bytes
            overhead_ratio = (transport_bytes / submission_bytes) if submission_bytes else None
        binding_preserved = getattr(survivability, "binding_preserved", None)
    return TransportSizeMetrics(
        logical_payload_bytes=len(canonical_json(mail.protected_payload_obj())),
        public_header_bytes=len(canonical_json(mail.public_header_obj())),
        submission_bytes=submission_bytes,
        transport_bytes=transport_bytes,
        overhead_bytes=overhead_bytes,
        overhead_ratio=overhead_ratio,
        binding_preserved=binding_preserved,
    )


def metrics_to_dict(metric: Any) -> Dict[str, Any]:
    return asdict(metric)
