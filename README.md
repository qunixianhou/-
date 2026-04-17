# AnchorMail prototype (research-grade object model)

This prototype implements the 8-interface design

- `Setup`
- `KeyGen`
- `Bootstrap`
- `Evolve`
- `Sync`
- `Send`
- `Receive`
- `Delegate`

with an explicit object model aligned to the paper's construction and security analysis.

## What is now explicit in the prototype

- **State-bound mail objects.** Every `MessageBlob` binds a protected RFC 5322-style email payload to
  - a **recipient anchor** (`recipient_anchor`), i.e. the sender's justified view of the recipient state;
  - a **sender authorization reference** (`sender_auth_ref`), i.e. the sender state authorizing the signing device.
- **Mail-shaped plaintext.** The encrypted payload is a structured `EmailContent` object rendered to RFC 5322 bytes (headers, body, threading headers, optional attachments) instead of an opaque byte string.
- **Completeness-oriented receive path.** `Receive` returns a structured `ReceiveResult` with
  - `decision ∈ {Accept, Defer, Reject}`
  - protocol reasons
  - optional `ForkEvidence`
  - optional `GapEvidence`
- **Justified sender view.** Historical messages remain valid after later sender-device removal because message verification is tied to the referenced sender state, not the sender's current head.
- **Anchor-specific coverage.** Decryption material is cached per **state object** rather than per epoch number, so forked states with the same epoch number cannot be silently conflated.
- **Protocolized OOB delegation.** `Delegate` exports an authenticated `DelegationPackage` carrying
  - an authenticated self-state bundle,
  - state-specific wrapped historical decryption material for the target device,
  - optional remote-view hints.
- **Suppression evidence.** Accepted later messages can raise explicit `GapAlert`/`GapEvidence` when authenticated progression gaps are observed.

## Threat-model focus

The prototype models an untrusted infrastructure with

- directory equivocation,
- object withholding,
- inbox filtering, and
- state-folder filtering.

This is enough to exercise the paper's main attack surfaces without building a full SMTP/IMAP deployment.

## Quick start

```bash
cd /mnt/data
python demo_scenarios.py
```

## Files

- `rsmail_demo/types.py`: object syntax (`StateBlob`, `MessageBlob`, `EmailContent`, `DelegationPackage`, receive evidence objects).
- `rsmail_demo/device.py`: protocol logic for the 8 interfaces.
- `rsmail_demo/crypto.py`: X25519 KEM, HKDF-SHA256, ChaCha20-Poly1305, Ed25519.
- `rsmail_demo/infra.py`: adversarially programmable directory / object-store / inbox wrapper.
- `rsmail_demo/attacker.py`: compromise-side bookkeeping for decryption demonstrations.
- `demo_scenarios.py`: runnable scenarios covering completeness, detectability, compromise, healing, and delegation.

## Still intentionally external / simplified

- **Genesis trust** is still treated as an external assumption.
- The infrastructure is a research wrapper, not a full mail-server implementation.
- Suppression alerts are protocol-level evidence of anomalous gaps, not user-facing attribution of intent.
