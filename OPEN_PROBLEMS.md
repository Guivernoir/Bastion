# Open Problems and Validation Status — MLSigcrypt-v3

Last updated: 2026-03-22

---

## Purpose

This document tracks the issues that still matter for evaluating MLSigcrypt-v3.
It now separates:

- issues that were closed by code changes or by direct analysis,
- issues that remain open in practice,
- the single theoretical issue that still appears genuinely unresolved.

The headline result of the current review is:

1. The only remaining theoretical open problem is the coupling between the
   signing mask `y` and the encapsulation randomness derived from it.
2. The main remaining practical validation gap is that there is still no second
   implementation of the full MLSigcrypt-v3 packet format for interoperability
   or differential testing.
3. Several previously listed items were stale and are no longer open.

This does not make the scheme formally proven or production-ready. It narrows
the live problem list to the items that still block strong security claims.

---

## Category 1: Security Proof Status

### 1.1 IND-CCA2 Proof Shape

**Status**: Closed as a standalone open problem; informal reduction documented.

The repository now includes [`docs/category1_security_analysis.md`](docs/category1_security_analysis.md),
which records the standard outsider-signcryption reduction shape:

- the receiver verifies the packet transcript before decapsulation,
- any packet rewrite that preserves validity requires a fresh valid signature,
- absent such a forgery, confidentiality reduces to the underlying
  Module-LWE-style encapsulation view.

There is still no bespoke paper-length proof for MLSigcrypt-v3, but this item is
no longer treated as a separate unexplained gap.

### 1.2 EUF-CMA Proof Shape

**Status**: Closed as a standalone open problem; informal reduction documented.

The same analysis note records that the signing side remains in the
Fiat-Shamir-with-aborts / ML-DSA proof family. The challenge transcript is
larger than baseline ML-DSA, but it is still a public random-oracle transcript
and does not introduce a new hardness assumption by itself.

Again, this is not a machine-checked or peer-reviewed proof. It is an analysis
result: the issue is no longer "unknown proof shape", it is "formal write-up not
yet authored".

### 1.3 Coupling Between Signing Randomness and Encapsulation Randomness

**Status**: Open. This is the one unresolved theoretical problem.

The encapsulation randomness `(r, e1, e2)` is derived from
`SHAKE256(ENCAP_MASK_DOMAIN || packed_y)`, where `y` is the signing mask used in
the same rejection-sampling loop.

That coupling is not covered directly by standard ML-DSA proofs or standard
Regev/MLWE proofs. The current design argument relies on the random-oracle view
of SHAKE-256, but the exact simulation lemma needed for the combined transcript
has not been written and has not been found in the literature.

If this item is not closed, the scheme should not be described as formally
proven. This is the only theoretical item still tracked as genuinely open.

### 1.4 Shared Matrix Security

**Status**: Closed as a standalone open problem.

The shared-matrix question reduces to the ordinary multi-instance Module-LWE
setting. Reusing the public matrix `A` across the signing and encapsulation keys
does not appear to introduce a new assumption beyond that standard view, and the
analysis note now treats this as covered rather than open.

---

## Category 2: Implementation Status

### 2.1 Official ML-DSA Validation Mismatch

**Status**: Closed.

The ACVP mismatch was isolated by tracing the first ML-DSA-87 key-generation
vector (`tcId 51`) field-by-field against the published semiexpanded key
material. The first divergence appeared in `s1[0][0]`, which identified a sign
inversion in `ExpandS`:

- local code sampled bounded coefficients as `b mod 5 - eta`,
- the correct FIPS 204 convention is `eta - (b mod 5)`.

After fixing that sampling bug, the traced key material matches the published
vector, and the embedded ACVP example tests now agree with the official hashes
and rejection counts. The only remaining difference in the harness was hex
letter case, which is now normalized in the assertions.

### 2.2 Decapsulation Failure Bound

**Status**: Closed for the current parameterization.

This issue was previously tracked as "failure probability not calculated". The
current code now contains a deterministic bound in
`src/mlsigcrypt/specs/ml/field.rs` showing that, under the implementation's
actual coefficient bounds, the decapsulation noise remains far below the decode
threshold:

- per-product bound: `N * 2 * 2 = 1024`,
- per-dot-product bound with `ENC_K = 4`: `4096`,
- total noise bound in decapsulation: `8194`,
- decoding threshold: `q / 4 = 2,095,104`.

Under those bounds, threshold crossing is not merely "unlikely"; it is excluded
for the currently implemented noise ranges.

### 2.3 Packet Size Regression Relative to Level 1/2

**Status**: Deferred by design.

Level 3 still uses an uncompressed algebraic encapsulation and therefore keeps
the larger `8393`-byte packet overhead. This is a conscious tradeoff, not a
correctness bug. Compression work should wait until the remaining proof and
validation issues are settled.

### 2.4 Timing Floors

**Status**: Reduced to deployment guidance.

Timing floors are now configurable through:

- `BASTION_MLSIGCRYPT_KEYGEN_FLOOR_NS`
- `BASTION_MLSIGCRYPT_SIGNCRYPT_FLOOR_NS`
- `BASTION_MLSIGCRYPT_UNSIGNCRYPT_FLOOR_NS`

Current defaults are:

- keygen: `0`
- signcrypt: `20_000_000` ns
- unsigncrypt: `10_000_000` ns

That closes the implementation gap that previously hard-coded developer-machine
numbers. What remains is an operational requirement: deployments still need to
calibrate those floors for their own hardware if timing padding matters.

### 2.5 Duplicate Public-Key Consistency Check

**Status**: Closed.

Decoded keys now serve as the single structural-validation gate. The public API
paths no longer re-run `verify_consistency()` after successful decode.

This removes the redundant hash-and-compare pass without weakening the decode
boundary.

---

## Category 3: Protocol Design Choices

### 3.1 Transcript Uses Standard `tr`

**Status**: Closed.

The challenge transcript now binds the sender through the standard ML-DSA
`tr = SHAKE256(pk_sig)` value rather than the raw `pk_sig` byte string.

This change landed in:

- `src/mlsigcrypt/signcrypt.rs`
- `src/mlsigcrypt/kat.rs`
- [`docs/category3_protocol_design.md`](docs/category3_protocol_design.md)

### 3.2 Rejected Iterations and `ENCAP_MASK_DOMAIN`

**Status**: By design; not tracked as an active problem.

Rejected iterations are not serialized into the packet. The accepted transcript
is the only observable one. Any deeper analysis now folds into item `1.3`.

### 3.3 Forward Secrecy

**Status**: By design.

MLSigcrypt-v3 is a packet primitive with long-lived identity keys. Forward
secrecy would require an outer session protocol.

### 3.4 Explicit Key Confirmation

**Status**: By design.

The construction relies on packet validity and successful decryption rather than
an explicit confirmation round trip. If explicit sender/receiver confirmation is
needed, it belongs in a higher-level protocol.

---

## Category 4: Testing and External Validation

### 4.1 Official ACVP Example Mismatch

**Status**: Closed.

The embedded ML-DSA ACVP checks now pass:

- key generation matches the published ML-DSA-87 semiexpanded vector,
- the official example `SHA2-256(pk || sk)` hashes match,
- the official example signature hashes match,
- the published rejection counts match.

This closes the earlier practical blocker at the primitive-example level. It is
still not a substitute for formal validation or for an independent second
implementation of the full MLSigcrypt-v3 packet format.

### 4.2 No Full Cross-Implementation MLSigcrypt Reference

**Status**: Open.

There is still no second implementation of the full MLSigcrypt-v3 packet format
to test against. The ACVP harness only checks the embedded ML-DSA behavior.

### 4.3 Protocol KAT Constants

**Status**: Closed.

The deterministic MLSigcrypt KAT constants are pinned and asserted in
`src/mlsigcrypt/kat.rs`. The earlier documentation claiming this was still
pending was stale.

### 4.4 No Differential Fuzzing Against a Reference

**Status**: Open.

Fuzzing still checks internal robustness and roundtrip behavior only. A true
differential harness remains future work until a second implementation exists.

---

## Summary Table

| ID   | Category        | Description                                           | Severity | Status |
|------|-----------------|-------------------------------------------------------|----------|--------|
| 1.1  | Proof           | IND-CCA2 proof shape                                  | Medium   | Closed by analysis |
| 1.2  | Proof           | EUF-CMA proof shape                                   | Medium   | Closed by analysis |
| 1.3  | Proof           | Coupled signing/encapsulation randomness              | Critical | Open |
| 1.4  | Proof           | Shared matrix security                                | Low      | Closed by analysis |
| 2.1  | Implementation  | Official ML-DSA validation mismatch                   | High     | Closed |
| 2.2  | Implementation  | Decapsulation failure bound                           | Medium   | Closed |
| 2.3  | Implementation  | Packet size regression                                | Low      | Deferred |
| 2.4  | Implementation  | Timing-floor configurability                          | Low      | Reduced to deployment config |
| 2.5  | Implementation  | Duplicate key consistency check                       | Low      | Closed |
| 3.1  | Design          | Raw `pk_sig` in challenge instead of `tr`             | Medium   | Closed |
| 3.2  | Design          | Rejected-iteration observability concern              | Low      | By design |
| 3.3  | Design          | No forward secrecy                                    | Medium   | By design |
| 3.4  | Design          | No explicit key confirmation                          | Low      | By design |
| 4.1  | Validation      | ACVP-derived ML-DSA example mismatch                  | High     | Closed |
| 4.2  | Validation      | No full cross-implementation MLSigcrypt reference     | Medium   | Open |
| 4.3  | Validation      | MLSigcrypt deterministic KAT constants                | Low      | Closed |
| 4.4  | Validation      | No differential fuzzing against a reference           | Low      | Open |

---

## Remaining Work

Priority order from here:

1. Build or obtain a second implementation of the full MLSigcrypt-v3 packet
   format for interoperability testing.
2. Write the formal treatment of item `1.3`, the randomness-coupling problem.
3. Revisit compression and packet-size work only after the above two items are
   settled.
