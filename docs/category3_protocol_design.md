# Category 3 Protocol Design Notes

Last updated: 2026-03-22

This note records the design decisions behind the level-3 packet format and
what was changed to close the transcript-binding question in `OPEN_PROBLEMS.md`
§3.1.

## 3.1 Transcript Binding

The signcryption transcript now binds the sender through ML-DSA's standard
`tr = SHAKE256(pk_sig)` value rather than through the raw 2592-byte public key
blob.

That is the same public-key binding used by FIPS 204 ML-DSA signing:

- `tr` is derived from the public key during key generation.
- Signing computes the message representative from `tr`.
- Verification recomputes `tr` from the supplied public key and uses it for the
  challenge check.

In this codebase the packet challenge now absorbs:

- the signed commitment `w1_packed`
- the algebraic encapsulation `encap`
- the AAD digest
- the sender transcript `tr`
- the recipient encapsulation public key
- the ciphertext length and ciphertext

This keeps the protocol transcript standard on the sender side while preserving
the MLSigcrypt-specific binding to the payload encryption context.

## 3.2 Rejection Sampling

Rejected signing iterations are not observable on the wire.

The implementation may compute intermediate values during an iteration, but the
packet fields are only copied into the caller-provided buffer after the rejection
loop terminates successfully. A rejected iteration is therefore discarded in
full; no partial packet is emitted.

## 3.3 Forward Secrecy

No forward secrecy is provided.

This is intentional: the primitive is a packet-level construction built around
long-lived identity keys. Forward secrecy requires an outer protocol with
ephemeral key agreement and session key ratcheting.

## 3.4 Key Confirmation

There is no explicit confirmation message.

The receiver implicitly confirms the encapsulated key when it successfully
verifies the signature and decrypts the ciphertext. A sender-side confirmation
step would need to be added by a higher-level protocol if that property is
required.

## Status

The code change for §3.1 is in `src/mlsigcrypt/signcrypt.rs`, with matching KAT
updates in `src/mlsigcrypt/kat.rs`.

