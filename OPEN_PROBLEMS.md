# Open Problems and Known Challenges — MLSigcrypt-v3

Last updated: 2026-03-17

---

## Purpose of This Document

This document catalogues the unresolved theoretical and practical problems with
the MLSigcrypt-v3 scheme. It is intended for cryptographers evaluating the
construction, implementers deciding whether to deploy it, and future contributors
working toward resolving these issues.

Items are grouped by category and ordered within each category by approximate
severity or blocking importance. Each item describes what is known, what is
unknown, and what would be needed to resolve it.

This document is meant to be updated as problems are resolved or new ones are
identified. The absence of a problem from this list does not mean it has been
ruled out.

---

## Category 1: Missing Security Proofs

These are the most significant gaps. Without formal proofs, the security of the
scheme rests on structural plausibility arguments rather than reductions to hard
problems.

---

### 1.1 No Formal IND-CCA2 Proof

**What is unknown**: It has not been formally shown that no polynomial-time
adversary can distinguish encryptions of two chosen plaintexts under an adaptive
chosen-ciphertext attack.

**Why it matters**: IND-CCA2 is the standard confidentiality goal for public-key
encryption and encapsulation. Without it, the scheme cannot be recommended for
contexts where an adversary may interact with a decryption oracle (which is a
reasonable model for many deployed systems).

**Structural argument (informal)**: Confidentiality should reduce to Module-LWE.
Given the encapsulation public key `t_R = A · s_R + e_R`, an adversary who
recovers `mkey` from `(encap, z, c̃, h)` must distinguish `u = Aᵀ · r + e₁` and
`v = t_Rᵀ · r + e₂ + encode(mkey)` from random. This is a standard Regev
decryption problem. The challenge binding (through `c̃`) ties the encapsulation
to the signing context, which should prevent the adversary from injecting a
different encapsulation under a valid signature.

**Specific gap**: The CCA2 argument requires simulating the decryption oracle in
the reduction. The simulator must handle the case where the adversary submits a
packet with a valid signature but a different `encap`. Because `encap` appears in
`c̃`, a valid signature over a modified `encap` requires solving MSIS. This means
the CCA2 security should follow from the CPA security of the encapsulation plus
the EUF-CMA security of the signing component — but this hybrid argument has not
been written out formally, and the coupling between the signing randomness `y`
and the encapsulation randomness `(r, e₁, e₂)` must be addressed carefully.

**What is needed**: A formal IND-CCA2 game for MLSigcrypt-v3 and a proof that any
adversary breaking it can be converted into either an MLWE or MSIS distinguisher.
The proof must handle the random oracle programming for `ENCAP_MASK_DOMAIN` and
`DOMAIN_CHAL` explicitly.

---

### 1.2 No Formal EUF-CMA Proof

**What is unknown**: It has not been formally shown that no polynomial-time
adversary can forge a packet that a recipient will accept as originating from a
given sender.

**Why it matters**: EUF-CMA is the standard authenticity goal. Without it, the
scheme cannot be claimed to provide sender authentication in the strong sense.

**Structural argument (informal)**: Authenticity should reduce to Module-SIS.
A forger who produces `(z*, c̃*, h*)` with `z*` satisfying the norm bounds for a
fresh `c̃*` must produce a valid ML-DSA response without the signing key `s_S`.
The standard ML-DSA reduction extracts an MSIS solution from a successful forger
by programming the random oracle at the challenge and using the forking lemma. The
same approach should apply here, since the challenge includes `w₁_packed` which
depends on `y` and therefore on `s_S` only through the response `z = y + c · s_S`.

**Specific gap**: The standard ML-DSA EUF-CMA proof programmes the challenge as
`c̃ = H(µ ‖ w₁_packed)` where `µ = H(tr ‖ msg)`. In MLSigcrypt-v3, the challenge
also includes `encap`, `aad_digest`, `pk_sig_S`, `pk_enc_R`, `ct_len`, and `ct`.
The proof must be adapted to programme a random oracle that absorbs all these
inputs. This is likely straightforward but has not been checked in detail.

Additionally, MLSigcrypt-v3 absorbs `pk_sig_S` (2592 bytes) directly rather than
`tr = SHAKE256(pk_sig_S)` (64 bytes). The standard proof uses `tr` to bind the
public key into the transcript in a specific way. Whether the direct absorption
of `pk_sig_S` provides equivalent binding for the purpose of the reduction has
not been verified.

**What is needed**: A formal EUF-CMA game and a reduction to MSIS, with explicit
handling of the modified transcript.

---

### 1.3 Coupling Between Signing Randomness and Encapsulation Randomness

**What is unknown**: The encapsulation randomness `(r, e₁, e₂)` is derived from
`SHAKE256(ENCAP_MASK_DOMAIN ‖ packed_y)`, which is a deterministic function of
the signing mask `y`. This coupling has not been formally analysed.

**Why it matters**: The standard security proofs for ML-DSA and for Regev
encryption both assume their respective randomness sources are independent. In
MLSigcrypt-v3, they are not — the encapsulation randomness is derived from `y`,
which is also used to produce the signing commitment `w = A · y`.

**What is argued informally**: Because SHAKE-256 is modelled as a random oracle,
the output `(r, e₁, e₂)` appears uniformly random and independent from the
adversary's perspective, even though it is derived from `y`. The adversary does
not observe `y` directly; they only see `z = y + c · s_S`, `w₁ = HighBits(A · y)`,
and `encap = u ‖ v`. Recovering `y` from these values requires solving MSIS (for
the signing component) or MLWE (for the encapsulation component). Under the
random oracle model, the binding domain separator `ENCAP_MASK_DOMAIN` ensures
the encapsulation randomness is indistinguishable from fresh randomness.

**Specific gap**: This argument relies on the random oracle model for SHAKE-256.
In a standard model proof (without idealising the hash), the coupling would need
to be addressed differently. Even in the random oracle model, the argument needs
to be made precise — specifically, the simulator must be able to answer random
oracle queries for `ENCAP_MASK_DOMAIN ‖ packed_y` without knowing `y`, which
requires programming the oracle at points that may be queried adaptively by the
adversary.

**What is needed**: A formal treatment of the coupling in the security proof,
either as part of the hybrid argument or as a standalone lemma.

---

### 1.4 No Security Proof for the Shared Matrix Construction

**What is unknown**: The security of using a single matrix `A` for both the
encapsulation key (`t_R = A · s_R + e_R`) and the signing key (`t_S = A · s_S + s_2`)
has not been formally analysed.

**Why it matters**: If sharing `A` between the two key components introduces any
joint leakage or structural weakness, it could undermine either the confidentiality
or the authenticity guarantees.

**What is argued informally**: Both ML-DSA and ML-KEM already treat the public
matrix `A` as a non-secret public parameter. An adversary who observes `A`, `t_R`,
and `t_S` gains no advantage beyond what they would have seeing three independent
random matrices — under the MLWE assumption. This is essentially the same argument
made for multi-instance MLWE security (seeing multiple MLWE samples from the same
`A` does not help more than seeing them from independent matrices, up to a union
bound).

**Specific gap**: The formal argument for multi-instance Module-LWE security
with a shared matrix has been studied in the literature but has not been cited
or applied to this specific construction.

**What is needed**: A reference to (or proof of) multi-instance Module-LWE
hardness with a shared public matrix, and its application to the MLSigcrypt-v3
key structure.

---

## Category 2: Implementation Concerns

These are issues with the current implementation that may affect security or
correctness, independent of the theoretical gaps above.

---

### 2.1 NTT Twiddle Factors Not Verified Against FIPS 204 KAT Vectors

**What is unknown**: The `ZETAS` table and the `INTT_SCALE` constant in `ntt.rs`
are taken from the Dilithium reference implementation and have not been independently
verified against FIPS 204 known-answer test vectors.

**Why it matters**: An incorrect twiddle factor would produce wrong NTT outputs,
which would cause wrong signatures that nonetheless round-trip within the same
implementation (since both signing and verification use the same table). The error
would only be detected when interoperating with a reference implementation.

**Current status**: The sign/verify roundtrip tests pass, which provides some
confidence. The explicit note in `ntt.rs` reads: "⚠ Value 41978 is taken from the
Dilithium reference implementation (ntt.c). It MUST be verified against FIPS 204
KAT vectors before deployment."

**What is needed**: Run the FIPS 204 published known-answer test vectors through
the ML-DSA signing and verification paths and confirm output agreement. This is
a straightforward engineering task, not a research problem.

---

### 2.2 Decapsulation Does Not Verify Encapsulation Freshness

**What is known**: The decapsulation step recovers `mkey` from `encap = u ‖ v`
using `s_R`. If a noise term exceeds the decoding threshold, the recovered `mkey`
will be wrong, but the error manifests as a wrong key (and therefore a keystream
mismatch) rather than an explicit decapsulation failure.

**Why it matters**: A wrong `mkey` will produce a wrong keystream, which will
produce wrong plaintext. The recipient will not know decapsulation failed until
they observe that the plaintext is garbage. In a higher-level protocol, this could
lead to confused error handling.

**Why it is bounded in practice**: The noise parameters are chosen such that
decapsulation failure probability is negligible (the noise terms `e_R, r, e₁, e₂`
are all small, with coefficients in `{-2, -1, 0, 1, 2}`). In practice, failures
should not occur.

**What is not done**: The exact failure probability has not been calculated for
the chosen parameter set. The standard analysis for Regev-style schemes applies,
but the numbers have not been worked out concretely.

**What is needed**: A calculation of the decapsulation failure probability for the
specific noise parameters used in `algebraic.rs`. This is a routine lattice
cryptography calculation.

---

### 2.3 Packet Size Regression Relative to Level 1 and Level 2

**What is known**: The Level 3 packet overhead is 8393 bytes. Level 1 and Level 2
overhead is 6281 bytes. Level 3 is therefore 2112 bytes larger per packet than
the levels it was designed to improve on.

**Root cause**: The encapsulation `u ‖ v` uses exact 23-bit coefficient encoding
(5 polynomials × 736 bytes = 3680 bytes). Level 1 uses ML-KEM's compressed 11-bit
encoding for its 1568-byte ciphertext.

**Planned resolution**: Compress `u` to approximately 11 bits per coefficient
(matching ML-KEM's `d_u = 11` compression), which would bring `u` down to roughly
4 × 352 = 1408 bytes, and compress `v` to approximately 5 bits per coefficient,
bringing `v` to approximately 160 bytes. This would reduce encap to approximately
1568 bytes, matching Level 1's ML-KEM ciphertext size, and bring total packet
overhead to approximately 6281 bytes or below.

**Why this is deferred**: Lossy compression of `u` and `v` introduces approximation
error that adds to the noise in decapsulation. The exact compression parameters
need to be chosen to keep the decapsulation failure probability negligible. This
analysis should follow the security proof, since the proof may impose constraints
on the noise budget.

**Current status**: Uncompressed. The README and SECURITY.md acknowledge this as
a known regression.

---

### 2.4 Timing Floors Are Not Calibrated Per-Platform

**What is known**: The timing floors (7 ms for signcrypt, 1.5 ms for unsigncrypt)
were set based on developer-machine measurements. They are not guaranteed to hold
on significantly faster hardware (where the actual operation might complete in much
less time than the floor, making the padding trivial to measure) or on significantly
slower hardware (where the operation might exceed the floor, negating its effect).

**Why it matters**: If the true operation time is much shorter than the floor on
fast hardware, the padding is effective. If the true operation time sometimes
exceeds the floor (e.g., due to many rejection-sampling iterations), the floor
provides no masking for those calls.

**What is not done**: The floors have not been empirically validated on a range
of hardware, and there is no mechanism to auto-calibrate them at startup.

**What is needed**: Either empirical calibration on target hardware, or
documentation that the floors should be configured per-deployment.

---

### 2.5 The `verify_consistency` Check on Key Decode Happens Twice

**What is known**: `decode_public_key` calls `verify_consistency`, and `signcrypt`
and `unsigncrypt` call `verify_consistency` again after decoding. This means every
public-API call that starts with `decode_secret_key` or `decode_public_key`
performs the consistency check twice.

**Why it matters**: Consistency checks include a recomputed `key_id` hash over 2592
+ 2944 + 32 bytes, which is not free. More significantly, if an adversary can
influence memory between the decode and the consistency check (a time-of-check /
time-of-use scenario, extremely unlikely given Rust's ownership model), the double
check could be bypassed.

**Current status**: The redundancy is a minor performance issue, not a security
issue in Rust's memory model. The double check is defensively correct.

**What is needed**: Refactor to verify only once, at decode time, and have
callers trust decoded keys. This is a code quality improvement.

---

## Category 3: Protocol Design Choices Under Scrutiny

These are design decisions that are not necessarily wrong, but that have not been
fully analysed and may be revisited as the proof work progresses.

---

### 3.1 Challenge Absorbs Raw `pk_sig_S` Rather Than Its Hash

**What is known**: The signing challenge absorbs the 2592-byte ML-DSA public key
`pk_sig_S` directly, rather than first hashing it to `tr = SHAKE256(pk_sig_S)` as
in standard ML-DSA.

**The stated rationale**: Direct absorption eliminates a hash call and binds the
full verification key into the transcript in a single step.

**The concern**: Standard ML-DSA uses `tr` as the message hash prefix specifically
because the proof uses `tr` as a binding commitment to the public key in a way that
supports the random oracle programming argument. Absorbing the raw key may provide
equivalent binding, but this has not been verified in the context of the MLSigcrypt
proof structure.

**What is needed**: Either a confirmation that direct absorption provides the same
security guarantee as the `tr = H(pk)` construction, or a switch to the standard
construction. This can likely be resolved as part of writing the EUF-CMA proof.

---

### 3.2 ENCAP_MASK_DOMAIN Derivation Reuses `y` Across Iterations

**What is known**: In each rejection-sampling iteration, a fresh `y` is sampled,
and then `encap_seed = SHAKE256(ENCAP_MASK_DOMAIN ‖ packed_y)` is derived from it.
If the iteration is rejected, both `y` and the derived `encap_seed` are discarded
and resampled.

**The concern**: An adversary who can observe multiple packets from the same sender
will see multiple `(encap_i, z_i, c̃_i)` tuples. For each packet, the tuple is
produced by a different (unknown) `y_i`. However, if two iterations within a single
signing operation happened to produce `encap_seed` values that share a common prefix
before rejection, there could theoretically be a related-randomness issue. In
practice, iterations are fully discarded on rejection, so no partial output is
observed.

**Why this is likely not an issue**: The packet only records the accepted iteration's
output. Rejected iterations leave no observable trace. The concern would only
materialise if partial encapsulation outputs from rejected iterations leaked through
some side channel.

**What is needed**: Confirmation that the rejection loop does not produce any
observable output from rejected iterations (it does not — the packet is only written
after a successful iteration), and a note in the proof that rejected encapsulations
do not need to be modelled.

---

### 3.3 No Forward Secrecy

**What is known**: MLSigcrypt-v3 does not provide forward secrecy. Long-lived
identity keys are used directly. An adversary who compromises a recipient's secret
key after a session can decrypt all previously captured packets.

**Rationale**: The scheme is designed as a packet-level primitive, not as a session
protocol. Forward secrecy would require an ephemeral key exchange layer on top, which
is outside the current scope.

**What is needed**: Documentation of this limitation for users, and potentially a
higher-level protocol specification that wraps MLSigcrypt-v3 with ephemeral key
agreement if forward secrecy is required.

---

### 3.4 No Key Confirmation

**What is known**: The protocol does not include an explicit mechanism by which
the sender confirms that the decapsulated `mkey` matches the encapsulated `mkey`.
The challenge binding provides an implicit confirmation (a wrong `mkey` would
produce a wrong keystream and therefore wrong ciphertext, which would be detected
at the application layer), but there is no in-protocol confirmation message.

**Why this is acceptable in the current design**: The challenge is computed over
the ciphertext, which is produced using `mkey`. If `mkey` is wrong, the ciphertext
will be wrong, and the challenge will not verify. So the protocol does implicitly
confirm `mkey` — but only to the extent that the recipient trusts the sender.

**What is not done**: A formal analysis of whether the implicit confirmation is
sufficient under the CCA2 model, or whether an explicit confirmation would
strengthen the security proof.

---

## Category 4: Testing and Validation Gaps

---

### 4.1 FIPS 204 Known-Answer Vectors Not Yet Run

As noted in §2.1, the ML-DSA signing and verification paths have not been tested
against FIPS 204 published known-answer test vectors. The internal sign/verify
roundtrips pass, but interoperability with reference implementations has not been
confirmed.

**Priority**: High. This is a straightforward engineering task that should be
completed before any serious deployment evaluation.

---

### 4.2 No Cross-Implementation Interoperability Test

**What is unknown**: Whether packets produced by this implementation can be
verified by a reference ML-DSA implementation, or whether the MLSigcrypt-specific
challenge construction would produce a different output than expected.

**What is needed**: A reference implementation of the MLSigcrypt-v3 protocol in
a second language (Python or Go would be conventional choices), and a test suite
that verifies packet compatibility in both directions.

---

### 4.3 Known-Answer Test Vectors Not Yet Pinned

The `kat.rs` test module contains a `generate_test_vectors` test (marked `#[ignore]`)
that prints all intermediate values in hex. The `known_answer_assertions` test
contains placeholder constants that are not yet filled in.

**Status**: The roundtrip determinism test (`known_answer_roundtrip_deterministic`)
passes and verifies correctness. The assertion test will become meaningful once the
generated values are copied into the constants.

**What is needed**: Run the generator, copy the output into the constant slots,
commit. This pins the protocol to a specific byte-level behaviour and makes future
inadvertent changes detectable.

---

### 4.4 No Differential Fuzzing Against a Reference

**What is known**: The fuzz target (`fuzz_mlsigcrypt_api`) exercises the public API
with random inputs and checks for panics, assertion failures, and roundtrip
consistency. It does not compare outputs against a reference implementation.

**What is needed**: A differential fuzzing harness that runs the same inputs through
both this implementation and a reference, comparing outputs byte-for-byte. This
would catch subtle encoding bugs that produce internally consistent but
non-interoperable outputs.

---

## Summary Table

| ID   | Category           | Description                                              | Severity   | Status       |
|------|--------------------|----------------------------------------------------------|------------|--------------|
| 1.1  | Missing proof       | No formal IND-CCA2 proof                                | Critical   | Open         |
| 1.2  | Missing proof       | No formal EUF-CMA proof                                 | Critical   | Open         |
| 1.3  | Missing proof       | Coupling between signing and encapsulation randomness   | High       | Open         |
| 1.4  | Missing proof       | Shared matrix security not formally analysed            | Medium     | Open         |
| 2.1  | Implementation      | NTT twiddle factors not verified against FIPS 204 KAT   | High       | Pending      |
| 2.2  | Implementation      | Decapsulation failure probability not calculated        | Medium     | Open         |
| 2.3  | Implementation      | Packet size regression vs Level 1/2 (8393 vs 6281 bytes)| Medium     | Deferred     |
| 2.4  | Implementation      | Timing floors not calibrated per-platform               | Low        | Open         |
| 2.5  | Implementation      | Double consistency check on key decode                  | Low (perf) | Open         |
| 3.1  | Design              | Challenge absorbs raw `pk_sig_S` vs standard `tr`       | Medium     | Under review |
| 3.2  | Design              | Mask domain derivation reuses `y` across iterations     | Low        | Likely OK    |
| 3.3  | Design              | No forward secrecy                                      | Medium     | By design    |
| 3.4  | Design              | No explicit key confirmation                            | Low        | By design    |
| 4.1  | Testing             | FIPS 204 KAT vectors not run                            | High       | Pending      |
| 4.2  | Testing             | No cross-implementation interoperability test           | High       | Open         |
| 4.3  | Testing             | KAT constants not yet pinned                            | Medium     | Pending      |
| 4.4  | Testing             | No differential fuzzing against reference               | Low        | Open         |

---

## Resolving These Problems

The rough order of attack:

1. **Run FIPS 204 KAT vectors** (2.1) — one afternoon of engineering work, unblocks
   confidence in the ML-DSA layer.

2. **Pin the KAT constants** (4.3) — one hour, commits the protocol to a specific
   byte-level output.

3. **Write the informal hybrid argument** (1.1, 1.2) — one or two days of focused
   writing. This will either close cleanly (increasing confidence in the scheme) or
   reveal a structural gap that warrants a redesign. Either outcome is valuable before
   investing in a formal proof.

4. **Address the challenge transcript question** (3.1) — can likely be resolved as
   part of step 3. If the direct absorption of `pk_sig_S` complicates the proof,
   switching to `tr = H(pk_sig_S)` is a one-line change.

5. **Calculate decapsulation failure probability** (2.2) — routine lattice calculation,
   should be done before any performance-critical deployment.

6. **Formal proof** (1.1, 1.2, 1.3, 1.4) — research-level effort, likely weeks to
   months. Should be peer-reviewed before the scheme is considered provably secure.

7. **Compressed encapsulation encoding** (2.3) — engineering work contingent on
   step 6, since the compression parameters must respect the noise budget established
   by the proof.