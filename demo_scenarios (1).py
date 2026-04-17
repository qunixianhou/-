from __future__ import annotations

from rsmail_demo.attacker import AttackerKnowledge
from rsmail_demo.device import Device
from rsmail_demo.genesis import list_genesis_profiles
from rsmail_demo.infra import AdversarialInfra
from rsmail_demo.metrics import (
    measure_delegation_package,
    measure_message_blob,
    measure_state_blob,
    measure_transport_growth,
    metrics_to_dict,
    snapshot_device_growth,
)
from rsmail_demo.transport import (
    AGGRESSIVE_GATEWAY_PROFILE,
    QP_TEXT_PROFILE,
    REFOLDED_PROFILE,
    analyze_transport_survival,
)
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
    pkg = bob1.Delegate(bob2)
    show_result("recv", bob2.Receive(old_mb))
    print("delegation_metrics", metrics_to_dict(measure_delegation_package(pkg)))


def scenario_transport_survivability_profiles() -> None:
    print("\n=== Scenario 8: transport survivability profiles ===")
    mail = EmailContent.simple("alice@example.test", ["bob@example.test"], "transport", "body with utf-8: 测试")
    mail.extra_headers["X-AnchorMail-Debug"] = "debug-token"
    submission = mail.to_submission_bytes()
    for name, profile in (("refolded", REFOLDED_PROFILE), ("quoted-printable", QP_TEXT_PROFILE), ("aggressive-gateway", AGGRESSIVE_GATEWAY_PROFILE)):
        result = analyze_transport_survival(submission, profile=profile)
        print(name, {
            "payload_equivalent": result.payload_equivalent,
            "binding_preserved": result.binding_preserved,
            "public_header_survival": result.public_header_survival,
            "extra_header_survival": result.extra_header_survival,
            "parse_error": result.parse_error,
            "mutation_report": result.mutation_report.__dict__,
            "transport_size": len(result.transported_raw),
        })


def scenario_size_growth_snapshot() -> None:
    print("\n=== Scenario 9: size-growth snapshot ===")
    infra = AdversarialInfra()
    alice = Device.KeyGen("alice@example.test", infra)
    bob = Device.KeyGen("bob@example.test", infra)
    alice.Bootstrap([alice])
    sb_id = bob.Bootstrap([bob])
    mail = EmailContent.simple("alice@example.test", ["bob@example.test"], "growth", "measure me")
    mb_id = alice.Send("bob@example.test", mail)
    sb = StateBlob.from_bytes(infra.get_object(sb_id))
    mb = MessageBlob.from_bytes(infra.get_object(mb_id))
    transport = analyze_transport_survival(mail, profile=REFOLDED_PROFILE)
    print("state", metrics_to_dict(measure_state_blob(sb)))
    print("message", metrics_to_dict(measure_message_blob(mb, mail)))
    print("device", metrics_to_dict(snapshot_device_growth(bob)))
    print("transport", metrics_to_dict(measure_transport_growth(mail, transport)))


def scenario_genesis_profiles() -> None:
    print("\n=== Scenario 10: genesis trust deployment profiles ===")
    for profile in list_genesis_profiles():
        print(profile)


if __name__ == "__main__":
    scenario_honest_basic()
    scenario_sender_auth_withholding()
    scenario_suppression_gap()
    scenario_fork_detectability_by_equivocation()
    scenario_compromise_breaks_traditional_afs()
    scenario_healing_future_epochs()
    scenario_historical_sender_completeness()
    scenario_delegate_historical_readability()
    scenario_transport_survivability_profiles()
    scenario_size_growth_snapshot()
    scenario_genesis_profiles()
