from __future__ import annotations

from rsmail_demo.attacker import AttackerKnowledge
from rsmail_demo.device import Device
from rsmail_demo.infra import AdversarialInfra
from rsmail_demo.types import EmailContent, MessageBlob, StateBlob


def show_result(label: str, result) -> None:
    subject = result.mail.subject if result.mail is not None else None
    print(label, {
        "decision": result.decision,
        "alerts": result.alerts,
        "reasons": result.reasons,
        "subject": subject,
        "gap": None if result.gap_evidence is None else result.gap_evidence.missing,
    })


def scenario_honest_basic() -> None:
    print("\n=== Scenario 0: honest send/receive on RFC-822 payload ===")
    infra = AdversarialInfra()
    alice = Device.KeyGen("alice@example.test", infra)
    bob = Device.KeyGen("bob@example.test", infra)
    alice.Bootstrap([alice])
    bob.Bootstrap([bob])
    mail = EmailContent.simple("alice@example.test", ["bob@example.test"], "hello", "hello bob")
    mb_id = alice.Send("bob@example.test", mail)
    show_result("recv", bob.Receive(mb_id))


def scenario_sender_auth_withholding() -> None:
    print("\n=== Scenario 1: delayed sender-auth reference -> Defer then Accept ===")
    infra = AdversarialInfra()
    alice = Device.KeyGen("alice@example.test", infra)
    bob = Device.KeyGen("bob@example.test", infra)
    alice.Bootstrap([alice])
    bob.Bootstrap([bob])
    mb_id = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "delayed", "wait for sender state"))
    mb = MessageBlob.from_bytes(infra.get_object(mb_id))
    sender_auth_ref = mb.hdr["sender_auth_ref"]
    infra.withhold_object(sender_auth_ref)
    show_result("first", bob.Receive(mb_id))
    infra.withheld_objects.discard(sender_auth_ref)
    show_result("second", bob.Receive(mb_id))


def scenario_suppression_gap() -> None:
    print("\n=== Scenario 2: suppression / out-of-order gap evidence ===")
    infra = AdversarialInfra()
    alice = Device.KeyGen("alice@example.test", infra)
    bob = Device.KeyGen("bob@example.test", infra)
    alice.Bootstrap([alice])
    bob.Bootstrap([bob])
    m1 = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "m1", "body1"))
    m2 = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "m2", "body2"))
    m3 = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "m3", "body3"))
    infra.drop_from_inbox("bob@example.test", m2)
    show_result("recv1", bob.Receive(m1))
    show_result("recv3", bob.Receive(m3))


def scenario_fork_detectability_by_equivocation() -> None:
    print("\n=== Scenario 3: fork detectability via recipient-anchor equivocation ===")
    infra = AdversarialInfra()
    bob1 = Device.KeyGen("bob@example.test", infra)
    bob2 = Device.KeyGen("bob@example.test", infra)
    alice = Device.KeyGen("alice@example.test", infra)
    alice.Bootstrap([alice])
    sb0 = bob1.Bootstrap([bob1, bob2])
    bob2.Sync("bob@example.test")
    sb1 = bob1.Evolve("PROGRESS")
    infra.set_dir_view(bob2.device_id, "bob@example.test", {sb0})
    infra.set_state_scan_view(bob2.device_id, "bob@example.test", [sb0])
    sb2 = bob2.Evolve("PROGRESS")
    print("fork tips", {sb1, sb2})
    infra.set_dir_view(alice.device_id, "bob@example.test", {sb1})
    infra.set_dir_view(bob2.device_id, "bob@example.test", {sb2})
    infra.set_state_scan_view(bob2.device_id, "bob@example.test", [sb2])
    mb_id = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "fork", "hello under fork"))
    show_result("recv", bob2.Receive(mb_id))


def scenario_compromise_breaks_traditional_afs() -> None:
    print("\n=== Scenario 4: compromise enables decryption of old mail ===")
    infra = AdversarialInfra()
    alice = Device.KeyGen("alice@example.test", infra)
    bob = Device.KeyGen("bob@example.test", infra)
    alice.Bootstrap([alice])
    sb0 = bob.Bootstrap([bob])
    mb_id = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "secret", "secret-before-compromise"))
    atk = AttackerKnowledge()
    atk.corrupt_device("bob@example.test", bob.device_id, bob.kem.sk)
    atk.learn_from_state(StateBlob.from_bytes(infra.get_object(sb0)))
    leaked = atk.try_decrypt_message("bob@example.test", MessageBlob.from_bytes(infra.get_object(mb_id)))
    print("attacker has epoch0 key", atk.can_decrypt_epoch("bob@example.test", 0))
    print("attacker decrypted", leaked.decode())


def scenario_healing_future_epochs() -> None:
    print("\n=== Scenario 5: remove/rekey heals future epochs ===")
    infra = AdversarialInfra()
    bob1 = Device.KeyGen("bob@example.test", infra)
    bob2 = Device.KeyGen("bob@example.test", infra)
    alice = Device.KeyGen("alice@example.test", infra)
    alice.Bootstrap([alice])
    sb0 = bob2.Bootstrap([bob1, bob2])
    atk = AttackerKnowledge()
    atk.corrupt_device("bob@example.test", bob1.device_id, bob1.kem.sk)
    atk.learn_from_state(StateBlob.from_bytes(infra.get_object(sb0)))
    mb0 = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "before", "before-heal"))
    print("attacker decrypt before", atk.try_decrypt_message("bob@example.test", MessageBlob.from_bytes(infra.get_object(mb0))).decode())
    sb1 = bob2.Evolve("REMOVE", remove_device_id=bob1.device_id)
    atk.learn_from_state(StateBlob.from_bytes(infra.get_object(sb1)))
    print("attacker has epoch1 key", atk.can_decrypt_epoch("bob@example.test", 1))
    mb1 = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "after", "after-heal"))
    print("attacker decrypt after", atk.try_decrypt_message("bob@example.test", MessageBlob.from_bytes(infra.get_object(mb1))))


def scenario_historical_sender_completeness() -> None:
    print("\n=== Scenario 6: historical sender authorization remains valid after removal ===")
    infra = AdversarialInfra()
    alice1 = Device.KeyGen("alice@example.test", infra)
    alice2 = Device.KeyGen("alice@example.test", infra)
    bob = Device.KeyGen("bob@example.test", infra)
    alice1.Bootstrap([alice1, alice2])
    alice2.Sync("alice@example.test")
    bob.Bootstrap([bob])
    mb_id = alice1.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "historic", "signed before removal"))
    alice2.Evolve("REMOVE", remove_device_id=alice1.device_id)
    show_result("recv", bob.Receive(mb_id))


def scenario_delegate_historical_readability() -> None:
    print("\n=== Scenario 7: delegation package transfers historical readability ===")
    infra = AdversarialInfra()
    alice = Device.KeyGen("alice@example.test", infra)
    bob1 = Device.KeyGen("bob@example.test", infra)
    bob2 = Device.KeyGen("bob@example.test", infra)
    alice.Bootstrap([alice])
    bob1.Bootstrap([bob1])
    old_mb = alice.Send("bob@example.test", EmailContent.simple("alice@example.test", ["bob@example.test"], "old", "old mail before join"))
    bob1.Evolve("JOIN", join_device=bob2)
    bob1.Delegate(bob2)
    show_result("recv", bob2.Receive(old_mb))


if __name__ == "__main__":
    scenario_honest_basic()
    scenario_sender_auth_withholding()
    scenario_suppression_gap()
    scenario_fork_detectability_by_equivocation()
    scenario_compromise_breaks_traditional_afs()
    scenario_healing_future_epochs()
    scenario_historical_sender_completeness()
    scenario_delegate_historical_readability()
