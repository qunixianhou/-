from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Set, Tuple


@dataclass
class DirectoryService:
    """A simple tip directory: subject -> set of tip state object ids."""

    tips: Dict[str, Set[str]] = field(default_factory=dict)

    def publish_tip(self, subject: str, sb_id: str) -> None:
        self.tips.setdefault(subject, set()).add(sb_id)

    def query_tips(self, subject: str) -> Set[str]:
        return set(self.tips.get(subject, set()))


@dataclass
class MailService:
    """Object store + per-principal inbox + per-principal state folder (append-only log)."""

    objects: Dict[str, bytes] = field(default_factory=dict)
    inbox: Dict[str, List[str]] = field(default_factory=dict)
    state_log: Dict[str, List[str]] = field(default_factory=dict)  # principal -> list of SB ids

    def put_object(self, obj_id: str, obj_bytes: bytes) -> None:
        self.objects[obj_id] = obj_bytes

    def get_object(self, obj_id: str) -> bytes:
        return self.objects[obj_id]

    def has_object(self, obj_id: str) -> bool:
        return obj_id in self.objects

    def post_inbox(self, recipient: str, mb_id: str) -> None:
        self.inbox.setdefault(recipient, []).append(mb_id)

    def fetch_inbox(self, recipient: str) -> List[str]:
        return list(self.inbox.get(recipient, []))

    def post_state(self, principal: str, sb_id: str) -> None:
        self.state_log.setdefault(principal, []).append(sb_id)

    def scan_states(self, principal: str) -> List[str]:
        return list(self.state_log.get(principal, []))


@dataclass
class AdversarialInfra:
    """Wrapper that allows programmable adversarial behaviors.

    - Directory equivocation: per (requester_device, subject) override.
    - Object withholding: deny access to selected object ids (global).
    - Inbox filtering: per (requester_device, principal) override.
    - State-folder scan filtering: per (requester_device, principal) override.

    This is intentionally simple: it is sufficient to drive threat-model demos.
    """

    dir: DirectoryService = field(default_factory=DirectoryService)
    mail: MailService = field(default_factory=MailService)

    dir_view_override: Dict[Tuple[str, str], Set[str]] = field(default_factory=dict)
    withheld_objects: Set[str] = field(default_factory=set)
    inbox_override: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)
    state_scan_override: Dict[Tuple[str, str], List[str]] = field(default_factory=dict)

    # --- directory ---

    def publish_state_tip(self, subject: str, sb_id: str) -> None:
        self.dir.publish_tip(subject, sb_id)

    def dir_query(self, subject: str, requester_device: str) -> Set[str]:
        key = (requester_device, subject)
        if key in self.dir_view_override:
            return set(self.dir_view_override[key])
        return self.dir.query_tips(subject)

    def set_dir_view(self, requester_device: str, subject: str, tips: Set[str]) -> None:
        self.dir_view_override[(requester_device, subject)] = set(tips)

    # --- object store ---

    def put_object(self, obj_id: str, obj_bytes: bytes) -> None:
        self.mail.put_object(obj_id, obj_bytes)

    def get_object(self, obj_id: str) -> bytes:
        if obj_id in self.withheld_objects:
            raise KeyError(f"object withheld by adversary: {obj_id}")
        return self.mail.get_object(obj_id)

    def has_object(self, obj_id: str) -> bool:
        return self.mail.has_object(obj_id) and (obj_id not in self.withheld_objects)

    def withhold_object(self, obj_id: str) -> None:
        self.withheld_objects.add(obj_id)

    # --- inbox ---

    def post_inbox(self, recipient: str, mb_id: str) -> None:
        self.mail.post_inbox(recipient, mb_id)

    def inbox_fetch(self, recipient: str, requester_device: str) -> List[str]:
        key = (requester_device, recipient)
        if key in self.inbox_override:
            return list(self.inbox_override[key])
        return self.mail.fetch_inbox(recipient)

    def set_inbox_view(self, requester_device: str, recipient: str, mb_ids: List[str]) -> None:
        self.inbox_override[(requester_device, recipient)] = list(mb_ids)

    def drop_from_inbox(self, recipient: str, mb_id: str) -> None:
        if recipient not in self.mail.inbox:
            return
        self.mail.inbox[recipient] = [x for x in self.mail.inbox[recipient] if x != mb_id]

    # --- state folder (self-sync) ---

    def post_state(self, principal: str, sb_id: str) -> None:
        self.mail.post_state(principal, sb_id)

    def state_scan(self, principal: str, requester_device: str) -> List[str]:
        key = (requester_device, principal)
        if key in self.state_scan_override:
            return list(self.state_scan_override[key])
        return self.mail.scan_states(principal)

    def set_state_scan_view(self, requester_device: str, principal: str, sb_ids: List[str]) -> None:
        self.state_scan_override[(requester_device, principal)] = list(sb_ids)
