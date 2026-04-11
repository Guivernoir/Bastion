# Global Security-Model Note for the HICS Assumption Stack

This note records the **security-model architecture** for the HICS research program after the proof-readiness pass.

The stack now distinguishes between:

* **base cryptographic assumptions**:
  * **A1**: QPT hidden-witness search hardness,
  * **A3**: QPT native-shell encapsulation indistinguishability;
* **derived / structural obligations**:
  * **A2**: canonical encoding, semantic coverage, admissibility discipline, and the derived binding theorems they must support.

That split is intentional. Not every ugly failure mode deserves to be promoted into a custom hardness assumption.

---

## 1. Global adversary model

Unless a later file says otherwise, every custom-family adversary in the HICS assumption stack is a
**QPT adversary**:

> a quantum polynomial-time adversary with classical input/output access to the public algorithms and objects specified in the relevant game.

This does **not** mean that every later theorem is automatically proven in the quantum random-oracle model or against every imaginable quantum side channel. It means the family assumptions themselves are written for a post-quantum threat model by default.

---

## 2. Policy on what is and is not a family assumption

The HICS stack adopts the following policy rules.

### 2.1 Parser and canonicalization failures

Parser bugs, non-canonical encodings, semantic aliasing, and malformed-object reinterpretation are **not** treated as custom hardness assumptions.

They are structural obligations of the design and must be discharged by explicit syntax, canonical encoding, and derived theorem statements.

### 2.2 External primitive assumptions

Dependence on:

* collision resistance (in a named regime — CR, TCR, or SPR),
* hash binding,
* KDF security,
* random-oracle or QROM behavior,
* extractor arguments,
* and other standard primitive properties

is **deferred to the instantiation and theorem layer**.

Those requirements may still be real and important, but they are not silently absorbed into the HICS-family assumptions.

---

## 3. Base games and strengthened variants

The next-layer formalism now consists of:

* readable **base games**,
* explicit **strengthened adaptive / multi-target variants**,
* explicit **bad-event accounting** where canonical freshness or admissibility alignment matters,
* explicit **N-factor reduction loss accounting** for all multi-target variants,
* and explicit **joint oracle leakage discipline** for all adaptive-public-exposure variants of A1.

This milestone remains **assumptions-only**:

* no algorithm files,
* no theorem files,
* no lemma files,
* and no README or Bastion scheme documents

are updated here.

---

## 4. Multi-user and multi-target note

Signcryption is inherently a **multi-user, multi-target** setting.

Accordingly, each base assumption used in a final signcryption proof must come with either:

* an explicit multi-target / multi-instance variant, or
* a clearly stated reduction loss showing how the single-target form degrades with the number of exposed keys, projections, oracle queries, or challenge targets.

Silent single-instance optimism is not a security model.

In particular, the `N`-factor loss in A3.4 (§6.1 of AssumptionA3.md) and the linear union-bound loss in A2.2 (§6.2 of AssumptionA2.md) must both be carried explicitly into any final signcryption proof that uses the multi-target variants.

---

## 5. Dependency map

The resulting dependency structure is:

* **A1** supports hidden-state non-recovery and alternate-witness resistance for the public projection layer, subject to:
  * the `GenWit` min-entropy obligation (A1 §4.1–4.2),
  * and the joint oracle leakage discipline for AP variants (A1 §3.6);
* **A2** supplies the binding basis and the derived semantic theorem targets (A2.1 single-projection, A2.2 multi-projection), but is no longer a base HICS-family hardness assumption; it depends on:
  * `Sem_λ` efficient computability and verification alignment (A2 §4.7),
  * and an explicitly named collision-resistance regime for `Bind_λ` (A2 §4.8);
* **A3** supports confidentiality of the public encapsulation shell and the recoverable shared secret, subject to:
  * the CovDist-Compat obligation on the cover distribution (A3 §2a),
  * support alignment of the cover branch (A3 §5.1),
  * and the domain-separated derivation structural obligation for derived-randomness instantiations (A3 §7).

In particular:

* A1 and A3 are the only irreducible custom-family assumptions at this layer;
* A2 is the place where design discipline is made explicit so that it can later be proved from standard binding machinery rather than hand-waved into the assumption stack.

---

## 6. Composition gap and joint sufficiency

**[NEW]** The dependency map in §5 identifies what each component supplies. However, the assumption stack does not yet contain a stated composition theorem or sketch showing that A1 + A2 + A3 jointly suffice for full signcryption security.

This gap is noted explicitly as a **proof obligation for the theorem layer**:

> It is the responsibility of the first theorem file to state and prove a composition theorem of the following form: given the structural obligations of A2, the hardness of A1 and A3 in their appropriate strengthened variants, and the relevant external instantiation hypotheses, the combined HICS signcryption scheme satisfies a named signcryption security notion (e.g., sUF-CMA + IND-CCA2 in the multi-user setting).

Until that composition theorem is written, the following risk exists:

* a proof may discharge A1, A2, and A3 individually and still have a gap in the combined reduction if the glue arguments require properties that none of the three explicitly supplies.

**Known glue properties that must be accounted for at composition time:**

1. The public projection `Y` appearing in A1 must be the same object as the projection `Y` appearing in A2's binding theorem. If these are instantiated differently in different protocol roles, the composition step must explicitly align them.

2. The shared secret `K^*` recovered from A3 must flow into the same KDF or symmetric layer that A2's `\mathsf{Bind}_\lambda` authenticates. If the KDF and the binder are applied to disjoint domains, the composition may not close.

3. The multi-target variants of A1 (A1.5, A1.6) and A3 (A3.4) involve separate `N`-factor losses that compound in the combined signcryption proof. The total multi-target reduction loss must be bounded jointly, not separately.

These are composition-layer obligations and do not invalidate the individual assumption documents. But they must be addressed before the stack can be called proof-complete.
