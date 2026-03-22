# Category 1 Security Analysis

Scope: this note addresses the open items in Category 1 of `OPEN_PROBLEMS.md`
using primary sources only. It does not claim a machine-checked proof for the
exact MLSigcrypt-v3 construction. It records what is already supported by the
literature, what can be reduced to standard assumptions, and what still looks
genuinely open.

## Bottom Line

The missing-proof items split into two classes.

1. `1.1` and `1.2` are structurally standard. The packet format is a sign-then-
   encrypt style construction with the sender binding the full packet transcript
   into the signature challenge. Existing signcryption theory already proves the
   relevant composition pattern from an IND-CPA encryption primitive plus a
   UF-CMA signature primitive.
2. `1.4` is not a new hardness assumption. The shared matrix `A` just places
   the scheme in the multi-instance MLWE setting, which is the normal setting in
   module-lattice security analyses.
3. `1.3` remains the one theoretical gap I could not close with a direct
   citation. The encapsulation randomness is deterministically derived from the
   signing mask `y`, and I did not find a primary-source proof that covers that
   exact coupling.

So the remaining open theoretical issue is `1.3`, not `1.1`, `1.2`, or `1.4`.

## 1.1 IND-CCA2

The relevant security shape is the classic outsider signcryption composition:
if the confidentiality layer is IND-CPA and the authenticity layer is UF-CMA,
then an adversary who tampers with a packet in a way that still verifies must
either forge a signature or fall back to the confidentiality of the underlying
encryption.

The code enforces the critical ordering: `unsigncrypt` verifies the signature
challenge before decapsulation. That means malformed or modified packets do not
reach the decryption step unless they already carry a valid signature. In the
random-oracle model, the challenge input absorbs the full packet transcript,
including the encapsulation, ciphertext length, ciphertext, AAD digest, and the
sender/recipient public-key material. A successful packet rewrite therefore
requires a fresh valid signature on a different transcript, which is exactly
the UF-CMA event.

This is the same proof pattern used in the standard signcryption literature.
The classic result of An, Dodis, and Rabin shows that outsider IND-gCCA2
security follows from IND-CPA encryption plus UF-CMA signatures for the usual
sign-then-encrypt style composition, and their multi-user extension states that
binding the user identities into the construction preserves the security proof.
MLSigcrypt-v3 already binds the sender and recipient identities through
`key_id_S` and `key_id_R`, so the same game-hop structure applies here.
For the packet-open setting in this codebase, the relevant decryption-respecting
relation is just packet equality, so the generic outsider proof is the right
strength of result to target.

Practical reduction sketch:

1. Replace the real `unsigncrypt` game with one that rejects any packet whose
   signature fails verification. This is not a behavior change; it matches the
   implementation.
2. Show that any query which keeps the signature valid but changes `encap`,
   `ct`, `aad`, or the bound key identifiers is a signature forgery.
3. Condition on no forgery. Then the decryption oracle is useless on modified
   packets, and the adversary's remaining advantage is against the encapsulation
   and stream-encryption layer only.
4. The encapsulation layer is a standard Module-LWE based public-key encryption
   view, so its indistinguishability follows the usual MLWE assumption.

That is enough to justify the intended IND-CCA2 story at the design level.

## 1.2 EUF-CMA

The signing part is still a Fiat-Shamir-with-aborts style ML-DSA transcript.
The only difference from standard ML-DSA is that the challenge absorbs the
packet transcript instead of just `H(tr || msg)`.

That does not break the proof shape. The Dilithium proof already programs a
random oracle on a public transcript, and the challenge can be treated as a
longer transcript string. A forger that outputs a fresh valid packet must
produce a valid `c_tilde`, `z`, and `h` tuple for a transcript that was never
previously signed. The usual forking-lemma style extraction then yields an MSIS
relation from two accepting transcripts with the same commitment and different
challenge values.

In other words, the reduction target is still Module-SIS, and the only change
is that the random-oracle query point is larger than the FIPS 204 baseline. A
larger public transcript is not a new hardness assumption.

Conservative statement:

1. The construction is still in the ML-DSA proof family.
2. The public transcript extension is proof work, not a new cryptographic gap.
3. A formal paper should spell out the oracle programming for the full packet
   transcript, but there is no indication that the extension invalidates the
   standard UF-CMA reduction strategy.

## 1.3 Coupled Randomness

This is the remaining theoretical issue.

The encapsulation randomness `(r, e1, e2)` is derived from
`SHAKE256(ENCAP_MASK_DOMAIN || packed_y)`, where `y` is the signing mask used
in the same rejection-sampling loop. Standard ML-DSA security proofs treat the
signing randomness as local to the signing oracle, while standard MLWE/KEM
proofs treat encapsulation randomness as fresh and independent. I did not find
a primary-source proof that covers the exact coupling used here.

Why this matters:

1. The proof must argue that the adversary cannot use its view of
   `z = y + c * s_S`, `w1`, `encap`, and the transcript to distinguish the
   derived encapsulation randomness from fresh randomness.
2. The usual signcryption composition theorems do not model one primitive's
   randomness as a deterministic function of the other primitive's signing
   mask.
3. The needed lemma is stronger than ordinary MLWE or MSIS alone; it is a
   joint simulation statement for the coupled transcript.

Conclusion: this is the one theoretical item that remains open after the
literature pass.

## 1.4 Shared Matrix

The shared-matrix question is well supported by the literature.

The module-LWE definition already allows polynomially many samples under the
same public matrix `A`. The module-lattice KEM literature explicitly states
that multi-instance MLWE is the standard way to view this setting, and that it
is believed to be as hard as the single-instance problem via a standard hybrid
argument. That is the right model for a scheme that exposes the same public
matrix across multiple keys or multiple roles.

For MLSigcrypt-v3, `A` is public, the sender and recipient secrets remain
independent, and the construction only reuses the same public matrix seed for
efficiency. That does not create a new algebraic relation beyond the usual
multi-instance MLWE view.

So the shared-matrix design is not a separate unresolved theoretical issue. It
reduces to standard multi-instance MLWE hardness.

## Verdict By Item

| ID | Status |
|---|---|
| 1.1 | Reduced to the standard IND-CCA2 signcryption proof shape |
| 1.2 | Reduced to the standard UF-CMA Fiat-Shamir-with-aborts proof shape |
| 1.3 | Still open; this is the remaining theoretical gap |
| 1.4 | Covered by the standard multi-instance MLWE view |

## Sources

Primary sources used for this note:

1. [FIPS 204: Module-Lattice-Based Digital Signature Standard](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf)
2. [CRYSTALS-Dilithium: Digital Signatures from Module Lattices](https://cryptojedi.org/papers/dilithium-20170627.pdf)
3. [Module-Lattice-Based Cryptography over Rings: KEM and MLWE discussion](https://eprint.iacr.org/2018/677.pdf)
4. [A Generic Signcryption Framework and Its Instantiations](https://www.iacr.org/archive/eurocrypt2002/23320080/adr.pdf)
5. [Evaluating the security of CRYSTALS-Dilithium in the quantum random oracle model](https://arxiv.org/abs/2312.16619)
