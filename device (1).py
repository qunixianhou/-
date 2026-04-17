from __future__ import annotations

import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

from cryptography.hazmat.primitives.asymmetric import x25519

from . import crypto
from .infra import AdversarialInfra
from .types import (
    DelegationPackage,
    DevicePub,
    EmailContent,
    ForkEvidence,
    GapEvidence,
    MessageBlob,
    ReceiveResult,
    StateBlob,
    canonical_json,
)



def random_id(prefix: str = "D") -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


@dataclass
class StateView:
    sbs: Dict[str, StateBlob] = field(default_factory=dict)
    valid: Set[str] = field(default_factory=set)
    heads: Set[str] = field(default_factory=set)
    selected_head: Optional[str] = None

    def head(self) -> Optional[StateBlob]:
        if self.selected_head is None:
            return None
        return self.sbs.get(self.selected_head)


@dataclass
class RecvProgress:
    contiguous_high: int = 0
    future_seen: Set[int] = field(default_factory=set)
    open_gaps: Set[int] = field(default_factory=set)


class ProtocolError(Exception):
    pass


@dataclass
class Device:
    principal: str
    infra: AdversarialInfra

    device_id: str = field(default_factory=lambda: random_id("dev"))
    sig: crypto.SigKeyPair = field(default_factory=crypto.SigKeyPair.generate)
    kem: crypto.KemKeyPair = field(default_factory=crypto.KemKeyPair.generate)

    views: Dict[str, StateView] = field(default_factory=dict)
    state_dk_cache: Dict[str, x25519.X25519PrivateKey] = field(default_factory=dict)  # state-id -> epoch sk
    send_ctr: Dict[str, int] = field(default_factory=dict)
    recv_progress: Dict[str, RecvProgress] = field(default_factory=dict)

    def pub(self) -> DevicePub:
        return DevicePub(pk_sig=self.sig.pk_bytes(), pk_kem=self.kem.pk_bytes())

    # ------------------------------------------------------------------
    # 8 interfaces
    # ------------------------------------------------------------------

    def Setup(self) -> None:
        return None

    @staticmethod
    def KeyGen(principal: str, infra: AdversarialInfra) -> "Device":
        return Device(principal=principal, infra=infra)

    def Bootstrap(self, manifest_devices: List["Device"]) -> str:
        if self.principal in self.views and self.views[self.principal].sbs:
            raise ProtocolError("principal already bootstrapped in this device view")

        epoch_kp = crypto.epoch_keypair_generate()
        ek = epoch_kp.pk_bytes()
        epoch_sk_bytes = crypto.epoch_sk_to_bytes(epoch_kp.sk)
        manifest: Dict[str, DevicePub] = {d.device_id: d.pub() for d in manifest_devices}

        wraps: Dict[str, bytes] = {}
        aad = canonical_json({"principal": self.principal, "epoch": 0, "kind": "GENESIS"})
        for did, pub in manifest.items():
            wraps[did] = crypto.wrap_to_device(pub.pk_kem, epoch_sk_bytes, aad)

        sb = StateBlob(
            principal=self.principal,
            kind="GENESIS",
            seq=0,
            parents=[],
            epoch=0,
            manifest=manifest,
            ek=ek,
            wraps=wraps,
            signer=self.device_id,
            signature=b"",
        )
        sb.signature = self.sig.sign(sb.signed_bytes())
        sb_id = sb.obj_id()

        self.infra.put_object(sb_id, sb.to_bytes())
        self.infra.publish_state_tip(self.principal, sb_id)
        self.infra.post_state(self.principal, sb_id)

        self.views.setdefault(self.principal, StateView())
        self.views[self.principal].sbs[sb_id] = sb
        self._recompute_view(self.principal)
        self._try_cache_epoch_keys_from_state(sb_id, sb)
        return sb_id

    def Sync(self, subject: str, wanted_refs: Optional[List[str]] = None) -> Set[str]:
        tips = set(self.infra.dir_query(subject, requester_device=self.device_id))
        if subject == self.principal:
            tips |= set(self.infra.state_scan(subject, requester_device=self.device_id))
        wanted = set(wanted_refs or [])

        self.views.setdefault(subject, StateView())
        view = self.views[subject]
        missing: Set[str] = set()
        visited: Set[str] = set()

        def fetch(sb_id: str) -> None:
            if sb_id in visited:
                return
            visited.add(sb_id)
            if sb_id in view.sbs:
                for p in view.sbs[sb_id].parents:
                    fetch(p)
                return
            try:
                raw = self.infra.get_object(sb_id)
            except KeyError:
                missing.add(sb_id)
                return
            sb = StateBlob.from_bytes(raw)
            view.sbs[sb_id] = sb
            for p in sb.parents:
                fetch(p)

        for t in tips | wanted:
            fetch(t)

        self._recompute_view(subject)
        if subject == self.principal:
            for sb_id in sorted(self.views[subject].valid):
                self._try_cache_epoch_keys_from_state(sb_id, self.views[subject].sbs[sb_id])
        return missing

    def Evolve(
        self,
        kind: str,
        *,
        join_device: Optional["Device"] = None,
        remove_device_id: Optional[str] = None,
    ) -> str:
        self.Sync(self.principal)
        view = self.views[self.principal]
        if not view.heads:
            raise ProtocolError("cannot evolve without any state")

        if len(view.heads) > 1:
            merge_id = self._publish_merge(view.heads)
            self.Sync(self.principal)
            view = self.views[self.principal]
            parent_id = merge_id
        else:
            parent_id = next(iter(view.heads))

        parent = view.sbs[parent_id]
        if parent_id not in view.valid:
            raise ProtocolError("parent state is not valid")

        new_manifest = dict(parent.manifest)
        new_epoch = parent.epoch
        new_ek = parent.ek
        epoch_sk = self._require_state_epoch_sk(parent_id)

        if kind == "PROGRESS":
            new_epoch = parent.epoch + 1
            epoch_kp = crypto.epoch_keypair_generate()
            new_ek = epoch_kp.pk_bytes()
            epoch_sk = epoch_kp.sk
        elif kind == "JOIN":
            if join_device is None:
                raise ProtocolError("JOIN requires join_device")
            new_manifest[join_device.device_id] = join_device.pub()
        elif kind == "REMOVE":
            if remove_device_id is None:
                raise ProtocolError("REMOVE requires remove_device_id")
            if remove_device_id in new_manifest:
                del new_manifest[remove_device_id]
            new_epoch = parent.epoch + 1
            epoch_kp = crypto.epoch_keypair_generate()
            new_ek = epoch_kp.pk_bytes()
            epoch_sk = epoch_kp.sk
        elif kind == "RESET":
            new_manifest = {self.device_id: parent.manifest[self.device_id]}
            new_epoch = parent.epoch + 1
            epoch_kp = crypto.epoch_keypair_generate()
            new_ek = epoch_kp.pk_bytes()
            epoch_sk = epoch_kp.sk
        else:
            raise ProtocolError(f"unknown evolve kind: {kind}")

        epoch_sk_bytes = crypto.epoch_sk_to_bytes(epoch_sk)
        aad = canonical_json({"principal": self.principal, "epoch": new_epoch, "kind": kind})
        wraps: Dict[str, bytes] = {}
        for did, pub in new_manifest.items():
            wraps[did] = crypto.wrap_to_device(pub.pk_kem, epoch_sk_bytes, aad)

        sb = StateBlob(
            principal=self.principal,
            kind=kind,
            seq=parent.seq + 1,
            parents=[parent_id],
            epoch=new_epoch,
            manifest=new_manifest,
            ek=new_ek,
            wraps=wraps,
            signer=self.device_id,
            signature=b"",
        )
        sb.signature = self.sig.sign(sb.signed_bytes())
        sb_id = sb.obj_id()

        self.infra.put_object(sb_id, sb.to_bytes())
        self.infra.publish_state_tip(self.principal, sb_id)
        self.infra.post_state(self.principal, sb_id)

        self.views[self.principal].sbs[sb_id] = sb
        self._recompute_view(self.principal)
        self._try_cache_epoch_keys_from_state(sb_id, sb)
        return sb_id

    def Send(self, recipient: str, mail: Union[EmailContent, str, bytes]) -> str:
        self.Sync(recipient)
        r_view = self.views[recipient]
        r_head = r_view.head()
        if r_head is None or r_view.selected_head is None:
            raise ProtocolError(f"no state for recipient {recipient}")

        self.Sync(self.principal)
        s_view = self.views[self.principal]
        if s_view.head() is None or s_view.selected_head is None:
            raise ProtocolError("sender is not bootstrapped")

        mail_obj = self._coerce_mail(recipient, mail)
        stream_id = self._stream_id(recipient)
        ctr = self.send_ctr.get(stream_id, 0) + 1
        self.send_ctr[stream_id] = ctr

        hdr = {
            **mail_obj.public_header_obj(),
            "sender_principal": self.principal,
            "recipient_principal": recipient,
            "stream_id": stream_id,
            "ctr": ctr,
            "recipient_anchor": r_view.selected_head,
            "sender_auth_ref": s_view.selected_head,
            "sender_device": self.device_id,
            "content_format": "message/rfc822",
        }

        pt = mail_obj.to_submission_bytes()
        ct_e, shared = crypto.kem_encap_epoch(r_head.ek)
        tmp_mb = MessageBlob(
            epoch=r_head.epoch,
            hdr=hdr,
            ct_e=ct_e,
            nonce=b"",
            ciphertext=b"",
            signer=self.device_id,
            signature=b"",
        )
        nonce, ciphertext = crypto.aead_encrypt(shared, pt, tmp_mb.aad_bytes())
        mb = MessageBlob(
            epoch=r_head.epoch,
            hdr=hdr,
            ct_e=ct_e,
            nonce=nonce,
            ciphertext=ciphertext,
            signer=self.device_id,
            signature=b"",
        )
        mb.signature = self.sig.sign(mb.signed_bytes())
        mb_id = mb.obj_id()
        self.infra.put_object(mb_id, mb.to_bytes())
        self.infra.post_inbox(recipient, mb_id)
        return mb_id

    def Receive(self, mb_id: str) -> ReceiveResult:
        try:
            raw = self.infra.get_object(mb_id)
        except KeyError:
            return ReceiveResult("Defer", None, None, [], ["MissingMessageObject"], mb_id=mb_id)

        try:
            mb = MessageBlob.from_bytes(raw)
        except Exception:
            return ReceiveResult("Reject", None, None, [], ["MalformedMessageObject"], mb_id=mb_id)

        recipient = str(mb.hdr.get("recipient_principal", ""))
        sender = str(mb.hdr.get("sender_principal", ""))
        if recipient != self.principal:
            return ReceiveResult("Reject", None, None, [], ["WrongRecipient"], mb_id=mb_id)

        recipient_anchor = str(mb.hdr.get("recipient_anchor", ""))
        r_status, r_sb, r_missing = self._classify_state_ref(self.principal, recipient_anchor)
        if r_status == "MISSING":
            return ReceiveResult(
                "Defer",
                None,
                None,
                [],
                [f"MissingRecipientAnchor:{','.join(sorted(r_missing or {recipient_anchor}))}"],
                mb_id=mb_id,
            )
        if r_status == "INVALID":
            return ReceiveResult(
                "Reject",
                None,
                None,
                ["ForkAlert"],
                ["UnjustifiedRecipientAnchor"],
                fork_evidence=ForkEvidence(self.principal, recipient_anchor, "recipient_anchor", "invalid_or_inconsistent_state_reference"),
                mb_id=mb_id,
            )
        assert r_sb is not None
        if r_sb.epoch != mb.epoch:
            return ReceiveResult("Reject", None, None, [], ["AnchorEpochMismatch"], mb_id=mb_id)
        if self._fork_visible(self.principal, recipient_anchor):
            return ReceiveResult(
                "Reject",
                None,
                None,
                ["ForkAlert"],
                ["RecipientAnchorVisibleFork"],
                fork_evidence=ForkEvidence(self.principal, recipient_anchor, "recipient_anchor", "anchor_not_consistent_with_all_accepted_heads"),
                mb_id=mb_id,
            )

        sender_auth_ref = str(mb.hdr.get("sender_auth_ref", ""))
        s_status, s_sb, s_missing = self._classify_state_ref(sender, sender_auth_ref)
        if s_status == "MISSING":
            return ReceiveResult(
                "Defer",
                None,
                None,
                [],
                [f"MissingSenderAuthRef:{','.join(sorted(s_missing or {sender_auth_ref}))}"],
                mb_id=mb_id,
            )
        if s_status == "INVALID":
            return ReceiveResult(
                "Reject",
                None,
                None,
                ["ForkAlert"],
                ["UnjustifiedSenderAuthRef"],
                fork_evidence=ForkEvidence(sender, sender_auth_ref, "sender_auth_ref", "invalid_or_inconsistent_state_reference"),
                mb_id=mb_id,
            )
        assert s_sb is not None
        if self._fork_visible(sender, sender_auth_ref):
            return ReceiveResult(
                "Reject",
                None,
                None,
                ["ForkAlert"],
                ["SenderAuthVisibleFork"],
                fork_evidence=ForkEvidence(sender, sender_auth_ref, "sender_auth_ref", "auth_ref_not_consistent_with_all_accepted_heads"),
                mb_id=mb_id,
            )

        from_dev = str(mb.hdr.get("sender_device", ""))
        if mb.signer != from_dev or from_dev not in s_sb.manifest:
            return ReceiveResult("Reject", None, None, [], ["InvalidSenderAuthorization"], mb_id=mb_id)
        pk_sig_bytes = s_sb.manifest[from_dev].pk_sig
        if not crypto.sig_verify(pk_sig_bytes, mb.signed_bytes(), mb.signature):
            return ReceiveResult("Reject", None, None, [], ["InvalidSignature"], mb_id=mb_id)

        if not self._ensure_anchor_covered(recipient_anchor):
            return ReceiveResult("Defer", None, None, [], [f"MissingEpochCoverage:{recipient_anchor}"], mb_id=mb_id)

        try:
            dk = self.state_dk_cache[recipient_anchor]
            shared = crypto.kem_decap_epoch(dk, mb.ct_e)
            pt = crypto.aead_decrypt(shared, mb.nonce, mb.ciphertext, mb.aad_bytes())
        except Exception:
            return ReceiveResult("Reject", None, None, [], ["AEADFail"], mb_id=mb_id)

        try:
            parsed_mail = EmailContent.from_transport_or_bytes(pt)
            mail = parsed_mail.mail if hasattr(parsed_mail, "mail") else parsed_mail
        except Exception:
            return ReceiveResult("Reject", None, None, [], ["InvalidEmailPayload"], mb_id=mb_id)
        if not self._mail_matches_header(mail, mb.hdr):
            return ReceiveResult("Reject", None, None, [], ["HeaderBindingMismatch"], mb_id=mb_id)

        gap_evidence = self._record_gap(str(mb.hdr.get("stream_id", "")), int(mb.hdr.get("ctr", 0)))
        alerts = ["GapAlert"] if gap_evidence is not None else []
        return ReceiveResult("Accept", pt, mail, alerts, [], gap_evidence=gap_evidence, mb_id=mb_id)

    def Delegate(self, new_device: "Device") -> DelegationPackage:
        self.Sync(self.principal)
        view = self.views[self.principal]
        auth_ref = view.selected_head
        if auth_ref is None:
            raise ProtocolError("cannot delegate without an accepted self state")
        auth_state = view.sbs[auth_ref]
        if new_device.device_id not in auth_state.manifest:
            raise ProtocolError("target device is not authorized in current manifest; JOIN first")

        state_bundle = {sid: view.sbs[sid].to_bytes() for sid in sorted(view.valid)}
        state_wraps: Dict[str, bytes] = {}
        for sid, sk in sorted(self.state_dk_cache.items()):
            aad = canonical_json(
                {
                    "principal": self.principal,
                    "state_id": sid,
                    "kind": "DELEGATE",
                    "exporter_auth_ref": auth_ref,
                    "target_device": new_device.device_id,
                }
            )
            state_wraps[sid] = crypto.wrap_to_device(new_device.kem.pk_bytes(), crypto.epoch_sk_to_bytes(sk), aad)

        remote_hints = {
            subject: sv.selected_head
            for subject, sv in self.views.items()
            if subject != self.principal and sv.selected_head is not None
        }
        pkg = DelegationPackage(
            principal=self.principal,
            exporter_device=self.device_id,
            exporter_auth_ref=auth_ref,
            target_device=new_device.device_id,
            target_pk_kem=new_device.kem.pk_bytes(),
            state_bundle=state_bundle,
            state_wraps=state_wraps,
            remote_view_hints=remote_hints,
            signature=b"",
        )
        pkg.signature = self.sig.sign(pkg.signed_bytes())
        new_device.ImportDelegationPackage(pkg)
        return pkg

    def ImportDelegationPackage(self, pkg: Union[DelegationPackage, bytes]) -> None:
        if isinstance(pkg, bytes):
            pkg = DelegationPackage.from_bytes(pkg)
        if pkg.principal != self.principal:
            raise ProtocolError("delegate principal mismatch")
        if pkg.target_device != self.device_id:
            raise ProtocolError("delegate target mismatch")
        if pkg.target_pk_kem != self.kem.pk_bytes():
            raise ProtocolError("delegate key mismatch")

        self.views.setdefault(self.principal, StateView())
        view = self.views[self.principal]
        for sid, raw in pkg.state_bundle.items():
            sb = StateBlob.from_bytes(raw)
            if sb.obj_id() != sid:
                raise ProtocolError("delegation package carries tampered state object")
            view.sbs[sid] = sb
        self._recompute_view(self.principal)

        if pkg.exporter_auth_ref not in view.valid:
            raise ProtocolError("delegation exporter auth ref is not justified by bundled state")
        auth_state = view.sbs[pkg.exporter_auth_ref]
        if pkg.exporter_device not in auth_state.manifest:
            raise ProtocolError("delegation exporter not authorized in exporter auth ref")
        pk_sig = auth_state.manifest[pkg.exporter_device].pk_sig
        if not crypto.sig_verify(pk_sig, pkg.signed_bytes(), pkg.signature):
            raise ProtocolError("delegation package signature invalid")
        head = view.head()
        if head is None or self.device_id not in head.manifest:
            raise ProtocolError("target device not authorized by delegated head")

        for sid, wrap in pkg.state_wraps.items():
            aad = canonical_json(
                {
                    "principal": self.principal,
                    "state_id": sid,
                    "kind": "DELEGATE",
                    "exporter_auth_ref": pkg.exporter_auth_ref,
                    "target_device": self.device_id,
                }
            )
            raw = crypto.unwrap_from_device(self.kem.sk, wrap, aad)
            self.state_dk_cache[sid] = crypto.epoch_sk_from_bytes(raw)

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _coerce_mail(self, recipient: str, mail: Union[EmailContent, str, bytes]) -> EmailContent:
        if isinstance(mail, EmailContent):
            msg = mail
        elif isinstance(mail, bytes):
            msg = EmailContent.simple(self.principal, [recipient], "", mail.decode("utf-8", errors="replace"))
        else:
            msg = EmailContent.simple(self.principal, [recipient], "", str(mail))

        if msg.mail_from != self.principal:
            raise ProtocolError("protected mail From must match sending principal in the current prototype")
        if recipient not in msg.to:
            msg = EmailContent(
                mail_from=msg.mail_from,
                to=list(msg.to) + [recipient],
                cc=list(msg.cc),
                subject=msg.subject,
                text_body=msg.text_body,
                message_id=msg.message_id,
                date=msg.date,
                in_reply_to=msg.in_reply_to,
                references=list(msg.references),
                html_body=msg.html_body,
                attachments=list(msg.attachments),
                extra_headers=dict(msg.extra_headers),
            )
        return msg

    def _stream_id(self, recipient: str) -> str:
        return f"{self.principal}:{self.device_id}:{recipient}"

    def _mail_matches_header(self, mail: EmailContent, hdr: Dict[str, object]) -> bool:
        return (
            mail.message_id == hdr.get("message_id")
            and mail.mail_from == hdr.get("mail_from")
            and sorted(mail.to) == sorted(list(hdr.get("rcpt_to", [])))
            and sorted(mail.cc) == sorted(list(hdr.get("cc", [])))
            and mail.date == hdr.get("date")
        )

    def _classify_state_ref(self, subject: str, ref_id: str) -> Tuple[str, Optional[StateBlob], Set[str]]:
        if not ref_id:
            return "INVALID", None, set()
        missing = self.Sync(subject, wanted_refs=[ref_id])
        view = self.views[subject]
        if ref_id in view.valid:
            return "JUSTIFIED", view.sbs[ref_id], set()
        if missing:
            return "MISSING", view.sbs.get(ref_id), missing
        if ref_id in view.sbs:
            return "INVALID", view.sbs[ref_id], set()
        return "MISSING", None, {ref_id}

    def _fork_visible(self, subject: str, ref_id: str) -> bool:
        view = self.views[subject]
        if len(view.heads) <= 1:
            return False
        for head_id in view.heads:
            if not self._is_ancestor(subject, ref_id, head_id):
                return True
        return False

    def _is_ancestor(self, subject: str, anc_id: str, desc_id: str) -> bool:
        view = self.views[subject]
        stack = [desc_id]
        seen: Set[str] = set()
        while stack:
            cur = stack.pop()
            if cur == anc_id:
                return True
            if cur in seen or cur not in view.sbs:
                continue
            seen.add(cur)
            stack.extend(view.sbs[cur].parents)
        return False

    def _record_gap(self, stream_id: str, ctr: int) -> Optional[GapEvidence]:
        if ctr <= 0:
            return None
        progress = self.recv_progress.setdefault(stream_id, RecvProgress())
        if ctr <= progress.contiguous_high or ctr in progress.future_seen:
            return None
        gap_event: Optional[GapEvidence] = None
        if ctr > progress.contiguous_high + 1:
            missing = list(range(progress.contiguous_high + 1, ctr))
            progress.open_gaps.update(missing)
            gap_event = GapEvidence(stream_id, ctr, progress.contiguous_high, missing)
        progress.future_seen.add(ctr)
        while progress.contiguous_high + 1 in progress.future_seen:
            nxt = progress.contiguous_high + 1
            progress.future_seen.remove(nxt)
            progress.open_gaps.discard(nxt)
            progress.contiguous_high = nxt
        return gap_event

    def _ensure_anchor_covered(self, anchor_id: str) -> bool:
        if anchor_id in self.state_dk_cache:
            return True
        self.Sync(self.principal, wanted_refs=[anchor_id])
        view = self.views[self.principal]
        if anchor_id not in view.valid:
            return False
        return self._try_cache_epoch_keys_from_state(anchor_id, view.sbs[anchor_id])

    def _publish_merge(self, head_ids: Set[str]) -> str:
        view = self.views[self.principal]
        parents = [view.sbs[h] for h in head_ids]
        common: Set[str] = set(parents[0].manifest.keys())
        for p in parents[1:]:
            common &= set(p.manifest.keys())
        new_manifest = {did: parents[0].manifest[did] for did in common}

        max_seq = max(p.seq for p in parents)
        max_epoch = max(p.epoch for p in parents)
        new_epoch = max_epoch + 1
        epoch_kp = crypto.epoch_keypair_generate()
        new_ek = epoch_kp.pk_bytes()
        epoch_sk = epoch_kp.sk
        epoch_sk_bytes = crypto.epoch_sk_to_bytes(epoch_sk)
        aad = canonical_json({"principal": self.principal, "epoch": new_epoch, "kind": "MERGE"})
        wraps: Dict[str, bytes] = {}
        for did, pub in new_manifest.items():
            wraps[did] = crypto.wrap_to_device(pub.pk_kem, epoch_sk_bytes, aad)

        sb = StateBlob(
            principal=self.principal,
            kind="MERGE",
            seq=max_seq + 1,
            parents=sorted(list(head_ids)),
            epoch=new_epoch,
            manifest=new_manifest,
            ek=new_ek,
            wraps=wraps,
            signer=self.device_id,
            signature=b"",
        )
        sb.signature = self.sig.sign(sb.signed_bytes())
        sb_id = sb.obj_id()
        self.infra.put_object(sb_id, sb.to_bytes())
        self.infra.publish_state_tip(self.principal, sb_id)
        self.infra.post_state(self.principal, sb_id)
        self.views[self.principal].sbs[sb_id] = sb
        self._recompute_view(self.principal)
        self._try_cache_epoch_keys_from_state(sb_id, sb)
        return sb_id

    def _require_state_epoch_sk(self, state_id: str) -> x25519.X25519PrivateKey:
        if state_id in self.state_dk_cache:
            return self.state_dk_cache[state_id]
        self.Sync(self.principal, wanted_refs=[state_id])
        view = self.views[self.principal]
        if state_id in view.valid and self._try_cache_epoch_keys_from_state(state_id, view.sbs[state_id]):
            return self.state_dk_cache[state_id]
        raise ProtocolError(f"cannot recover epoch secret for state {state_id}")

    def _try_cache_epoch_keys_from_state(self, sb_id: str, sb: StateBlob) -> bool:
        if sb_id in self.state_dk_cache:
            return True
        if self.device_id not in sb.wraps:
            return False
        try:
            aad = canonical_json({"principal": sb.principal, "epoch": sb.epoch, "kind": sb.kind})
            raw = crypto.unwrap_from_device(self.kem.sk, sb.wraps[self.device_id], aad)
            self.state_dk_cache[sb_id] = crypto.epoch_sk_from_bytes(raw)
            return True
        except Exception:
            return False

    def _recompute_view(self, subject: str) -> None:
        view = self.views[subject]
        view.valid.clear()
        items = sorted(view.sbs.items(), key=lambda kv: (kv[1].seq, kv[0]))
        for sb_id, sb in items:
            if self._valid_sb(subject, sb):
                view.valid.add(sb_id)
        referenced: Set[str] = set()
        for sb_id in view.valid:
            for p in view.sbs[sb_id].parents:
                if p in view.valid:
                    referenced.add(p)
        view.heads = {sb_id for sb_id in view.valid if sb_id not in referenced}
        if not view.heads:
            view.selected_head = None
            return
        view.selected_head = sorted(view.heads, key=lambda hid: (view.sbs[hid].seq, hid))[-1]

    def _valid_sb(self, subject: str, sb: StateBlob) -> bool:
        if sb.principal != subject:
            return False
        if set(sb.wraps.keys()) != set(sb.manifest.keys()):
            return False
        if sb.kind == "GENESIS":
            if sb.seq != 0 or sb.parents:
                return False
            if sb.signer not in sb.manifest:
                return False
            return crypto.sig_verify(sb.manifest[sb.signer].pk_sig, sb.signed_bytes(), sb.signature)

        if not sb.parents:
            return False
        view = self.views[subject]
        for p in sb.parents:
            if p not in view.valid:
                return False
        parents = [view.sbs[p] for p in sb.parents]
        if sb.seq != max(p.seq for p in parents) + 1:
            return False
        auth_ids: Set[str] = set(parents[0].manifest.keys())
        for p in parents[1:]:
            auth_ids &= set(p.manifest.keys())
        if sb.signer not in auth_ids:
            return False
        pk_sig = parents[0].manifest[sb.signer].pk_sig
        if not crypto.sig_verify(pk_sig, sb.signed_bytes(), sb.signature):
            return False

        if len(sb.parents) > 1:
            return sb.kind == "MERGE" and set(sb.manifest.keys()) == auth_ids and sb.epoch == max(p.epoch for p in parents) + 1

        parent = parents[0]
        if sb.kind == "PROGRESS":
            return set(sb.manifest.keys()) == set(parent.manifest.keys()) and sb.epoch == parent.epoch + 1
        if sb.kind == "JOIN":
            return set(parent.manifest.keys()).issubset(set(sb.manifest.keys())) and sb.epoch == parent.epoch
        if sb.kind == "REMOVE":
            return set(sb.manifest.keys()).issubset(set(parent.manifest.keys())) and sb.epoch == parent.epoch + 1
        if sb.kind == "RESET":
            return sb.epoch == parent.epoch + 1 and sb.signer in sb.manifest and set(sb.manifest.keys()).issubset(set(parent.manifest.keys()))
        return False
