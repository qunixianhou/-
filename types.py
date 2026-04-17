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
    """Protected email payload carried inside the encrypted MessageBlob.

    The payload is rendered to and parsed from RFC 5322-style bytes so that the
    prototype is bound to a mail-shaped object rather than an opaque byte string.
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

    def public_header_obj(self) -> Dict[str, Any]:
        return {
            "mail_from": self.mail_from,
            "rcpt_to": list(self.to),
            "cc": list(self.cc),
            "message_id": self.message_id,
            "date": self.date,
        }

    def to_email_message(self) -> EmailMessage:
        msg = EmailMessage(policy=policy.SMTP)
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
        for k, v in self.extra_headers.items():
            if k not in msg:
                msg[k] = v
        msg["Subject"] = self.subject

        has_attachments = bool(self.attachments)
        if self.html_body is None and not has_attachments:
            msg.set_content(self.text_body)
            return msg

        msg.set_content(self.text_body)
        if self.html_body is not None:
            msg.add_alternative(self.html_body, subtype="html")
        for att in self.attachments:
            maintype, subtype = att.content_type.split("/", 1)
            msg.add_attachment(
                att.data,
                maintype=maintype,
                subtype=subtype,
                filename=att.filename,
                disposition=att.disposition,
                cid=att.content_id,
            )
        return msg

    def to_rfc822_bytes(self) -> bytes:
        return self.to_email_message().as_bytes(policy=policy.SMTP)

    @staticmethod
    def from_rfc822_bytes(raw: bytes) -> "EmailContent":
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
            extra_headers={},
        )

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


@dataclass
class StateBlob:
    principal: str
    kind: str  # GENESIS/PROGRESS/JOIN/REMOVE/MERGE/RESET
    seq: int
    parents: List[str]
    epoch: int
    manifest: Dict[str, DevicePub]  # device_id -> DevicePub
    ek: bytes  # epoch public key (X25519 raw bytes)
    wraps: Dict[str, bytes]  # device_id -> wrapped epoch private key bytes
    signer: str  # device_id
    signature: bytes  # Ed25519 signature

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
    hdr: Dict[str, Any]  # public mail transport + auth refs
    ct_e: bytes
    nonce: bytes
    ciphertext: bytes
    signer: str  # device_id (sender)
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
    decision: str  # Accept / Defer / Reject
    plaintext: Optional[bytes]
    mail: Optional[EmailContent]
    alerts: List[str]
    reasons: List[str]
    fork_evidence: Optional[ForkEvidence] = None
    gap_evidence: Optional[GapEvidence] = None
    mb_id: Optional[str] = None
