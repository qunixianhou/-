from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from cryptography.hazmat.primitives.asymmetric import x25519

from . import crypto
from .types import MessageBlob, StateBlob, canonical_json


@dataclass
class CompromisedDevice:
    principal: str
    device_id: str
    sk_kem: x25519.X25519PrivateKey


@dataclass
class AttackerKnowledge:
    compromised: List[CompromisedDevice] = field(default_factory=list)
    state_keys: Dict[str, x25519.X25519PrivateKey] = field(default_factory=dict)  # state-id -> epoch sk
    epoch_index: Dict[Tuple[str, int], Set[str]] = field(default_factory=dict)

    def corrupt_device(self, principal: str, device_id: str, sk_kem: x25519.X25519PrivateKey) -> None:
        self.compromised.append(CompromisedDevice(principal=principal, device_id=device_id, sk_kem=sk_kem))

    def learn_from_state(self, sb: StateBlob) -> None:
        sb_id = sb.obj_id()
        for cd in self.compromised:
            if cd.principal != sb.principal:
                continue
            if cd.device_id not in sb.manifest or cd.device_id not in sb.wraps:
                continue
            if sb_id in self.state_keys:
                continue
            try:
                aad = canonical_json({"principal": sb.principal, "epoch": sb.epoch, "kind": sb.kind})
                raw = crypto.unwrap_from_device(cd.sk_kem, sb.wraps[cd.device_id], aad)
                self.state_keys[sb_id] = crypto.epoch_sk_from_bytes(raw)
                self.epoch_index.setdefault((sb.principal, sb.epoch), set()).add(sb_id)
            except Exception:
                pass

    def can_decrypt_epoch(self, principal: str, epoch: int) -> bool:
        return bool(self.epoch_index.get((principal, epoch)))

    def try_decrypt_message(self, recipient: str, mb: MessageBlob) -> Optional[bytes]:
        candidates: List[x25519.X25519PrivateKey] = []
        anchor = str(mb.hdr.get("recipient_anchor", ""))
        if anchor in self.state_keys:
            candidates.append(self.state_keys[anchor])
        for sid in sorted(self.epoch_index.get((recipient, mb.epoch), set())):
            if sid != anchor:
                candidates.append(self.state_keys[sid])
        for dk in candidates:
            try:
                shared = crypto.kem_decap_epoch(dk, mb.ct_e)
                return crypto.aead_decrypt(shared, mb.nonce, mb.ciphertext, mb.aad_bytes())
            except Exception:
                continue
        return None
