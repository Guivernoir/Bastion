# Assumption Document A3

## QPT Native-Shell Encapsulation Indistinguishability

### 1. Purpose

This document defines the second irreducible custom-family assumption in the HICS (Hybrid Incidence-Constraint Systems) stack:

> a real HICS encapsulation shell carrying a recoverable shared secret is computationally indistinguishable, to a QPT adversary, from a native cover-shell object paired with an unrelated uniform key.

This is the confidentiality root for the HICS signcryption program.

It is deliberately written as a **native-shell assumption**, because in this design family the main risk is not only key indistinguishability but whether real encapsulations statistically look like honest public shell objects at all.

---

### 2. Objects and canonical-valid interface

Let:

* `\mathcal{E}_\lambda`: raw encapsulation-object space,
* `\widehat{\mathcal{E}}_\lambda`: canonical encapsulation space,
* `\{0,1\}^{\kappa}`: shared-key space,
* `\mathcal{AUX}_\lambda`: public auxiliary-context space.

The relevant algorithms and predicates are:

* `\mathsf{Setup}_\lambda`,
* `\mathsf{KeyGenEnc}_\lambda`,
* `\mathsf{Encap}_\lambda(pk_R;\rho,aux)`,
* `\mathsf{Decap}_\lambda(sk_R,\hat e,aux)`,
* `\mathsf{CanonEncap}_\lambda(pk_R,e,aux)`,
* `\mathsf{ValidEncap}_\lambda(\hat e,pk_R,aux)`.

The canonicalization map
[
\mathsf{CanonEncap}_\lambda(pk_R,e,aux)\in \widehat{\mathcal{E}}_\lambda \cup \{\bot\}
]
parses a public encapsulation object and returns either:

* its unique canonical encapsulation representative `\hat e`, or
* the public malformed-object symbol `\bot`.

Define the canonical-valid domain
[
\widehat{\mathcal{E}}^{adm}_\lambda(pk_R,aux)
:=
\{
\hat e \in \widehat{\mathcal{E}}_\lambda :
\mathsf{ValidEncap}_\lambda(\hat e,pk_R,aux)=1
\}.
]

Define the challenge-equivalence relation
[
e_1 \sim e_2
\iff
\mathsf{CanonEncap}_\lambda(pk_R,e_1,aux)
=
\mathsf{CanonEncap}_\lambda(pk_R,e_2,aux)
\in
\widehat{\mathcal{E}}^{adm}_\lambda(pk_R,aux).
]

This relation matters because CCA exclusions must be written against the **canonical challenge class**, not merely against one byte string.

We also define the native public cover distribution
[
e^\$ \leftarrow \mathcal{D}^{cover}_{\lambda,aux}(pk_R).
]

The required properties of `\mathcal{D}^{cover}` are specified in §2a below.

---

### 2a. Cover distribution admissibility

**[FIX-A3-1]** The native cover distribution `\mathcal{D}^{cover}_{\lambda,aux}(pk_R)` is not a free parameter. A cover distribution that is statistically far from real encapsulation shells in any efficiently detectable structural property renders the indistinguishability claim of A3.1 either vacuously false or trivially attackable.

The following conditions are therefore mandatory.

#### 2a.1 Named property: CovDist-Compat

We say `\mathcal{D}^{cover}_{\lambda,aux}` satisfies **CovDist-Compat** with respect to `\mathsf{Encap}_\lambda` if:

[
\left\{
e^\$
\;:\;
(pk_R,sk_R)\leftarrow \mathsf{KeyGenEnc}_\lambda(aux),\;
e^\$ \leftarrow \mathcal{D}^{cover}_{\lambda,aux}(pk_R)
\right\}
\approx_c
\left\{
e
\;:\;
(pk_R,sk_R)\leftarrow \mathsf{KeyGenEnc}_\lambda(aux),\;
(e,K)\leftarrow \mathsf{Encap}_\lambda(pk_R;\rho,aux)
\right\}
]

where `\approx_c` denotes computational indistinguishability, and the comparison is over the **encapsulation-object marginal only** — that is, ignoring the shared key `K` on the real side.

The intuition: the cover distribution must blend into the real encapsulation language on the public shell alone. Any QPT distinguisher between the two marginals yields a QPT distinguisher for A3.1 by the trivial reduction: set `K^* \leftarrow \{0,1\}^\kappa` uniformly and run the cover-distribution distinguisher on `e^*` alone.

#### 2a.2 Instantiation obligation

CovDist-Compat is an **instantiation-layer obligation**. Every concrete instantiation of A3 must:

1. provide an explicit description of `\mathcal{D}^{cover}_{\lambda,aux}`,
2. prove or argue that `\mathcal{D}^{cover}_{\lambda,aux}` satisfies CovDist-Compat, and
3. if the CovDist-Compat proof relies on a standard primitive assumption (e.g., pseudorandomness of the encapsulation algorithm, or a random-oracle argument), state that assumption explicitly and separately from A3.

An instantiation that omits step 2 does not establish a meaningful indistinguishability claim.

#### 2a.3 Circular-constraint note

CovDist-Compat is not self-referentially circular. It requires only that the encapsulation-object marginal (without the key) is computationally indistinguishable between the real and cover branches. This is a strictly weaker condition than full A3.1 indistinguishability, and it can typically be argued from the pseudorandomness of the encapsulation algorithm's output distribution over the public shell space, independent of key recovery.

If a concrete instantiation cannot establish even this marginal indistinguishability, then the A3 game has a trivial distinguisher and the assumption is false for that instantiation. This is a cryptographic engineering failure, not a family-level issue.

---

### 3. Base confidentiality game

## Assumption A3.1. QPT Native-Shell Indistinguishability (`qNS-IND`)

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qNS\text{-}IND}_{\mathcal A}(\lambda)
:=
\left|\Pr[b'=b]-\frac12\right|,
]
in the following experiment.

1. sample
   [
   aux \leftarrow \mathsf{Setup}_\lambda,\qquad
   (pk_R,sk_R)\leftarrow \mathsf{KeyGenEnc}_\lambda(aux),
   ]
2. give `(pk_R,aux)` to `\mathcal{A}`,
3. sample challenge bit `b \leftarrow \{0,1\}`,
4. if `b=0`, sample
   [
   (e^*,K^*) \leftarrow \mathsf{Encap}_\lambda(pk_R;\rho,aux),
   ]
5. if `b=1`, sample
   [
   e^* \leftarrow \mathcal{D}^{cover}_{\lambda,aux}(pk_R),
   \qquad
   K^* \leftarrow \{0,1\}^{\kappa},
   ]
6. give `(e^*,K^*)` to `\mathcal{A}`,
7. let `b' \leftarrow \mathcal{A}(e^*,K^*,pk_R,aux)`.

The assumption requires
[
\mathrm{Adv}^{qNS\text{-}IND}_{\mathcal A}(\lambda)
\le \mathrm{negl}(\lambda).
]

**Precondition.** This game is well-formed only if `\mathcal{D}^{cover}_{\lambda,aux}` satisfies CovDist-Compat (§2a.1). An instantiation that does not satisfy CovDist-Compat must not invoke A3.1.

### Interpretation

The adversary cannot distinguish:

* a real HICS encapsulation shell carrying a real shared key,
* from a native cover-shell object paired with an unrelated uniform key.

---

### 4. Base CCA game

## Assumption A3.2. QPT Native-Shell Indistinguishability under Canonical Valid CCA Queries (`qNS-IND-CCA`)

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA}_{\mathcal A}(\lambda,q_{dec})
:=
\left|\Pr[b'=b]-\frac12\right|,
]
in the following experiment.

1. run the setup and challenge generation steps of `qNS-IND`,
2. give the adversary access to the decapsulation oracle
   [
   \mathcal{O}^{dec}_{sk_R}(\cdot),
   ]
   with total query budget `q_{dec}`.

The oracle is defined exactly as follows on input `e`:

1. compute
   [
   \hat e \leftarrow \mathsf{CanonEncap}_\lambda(pk_R,e,aux),
   ]
2. if `\hat e = \bot`, return the public malformed-object symbol `\bot`,
3. if
   [
   \mathsf{ValidEncap}_\lambda(\hat e,pk_R,aux)=0,
   ]
   return the same public malformed-object symbol `\bot`,
4. if the challenge has already been issued and
   [
   \hat e = \hat e^*
   \qquad
   \text{where }
   \hat e^* := \mathsf{CanonEncap}_\lambda(pk_R,e^*,aux),
   ]
   then return the public forbidden-query symbol `\mathsf{forbidden}`,
5. otherwise return
   [
   \mathsf{Decap}_\lambda(sk_R,\hat e,aux).
   ]

The assumption requires
[
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA}_{\mathcal A}(\lambda,q_{dec})
\le \mathrm{negl}(\lambda)
\]
for every QPT adversary making at most `q_{dec}` decapsulation queries.

### Interpretation

Even with decapsulation-oracle access, no efficient quantum adversary can distinguish the real challenge pair from the cover-shell challenge pair, provided it does not query the oracle on the challenge encapsulation or any canonically equivalent valid representative.

---

### 5. Support alignment and strengthened CCA accounting

#### 5.1 Canonical-valid support alignment

The real and cover challenge branches must live in the same public admissibility regime.

For honest generation,
[
\Pr\Big[
\hat e \in \widehat{\mathcal{E}}^{adm}_\lambda(pk_R,aux)
\;:\;
(e,K)\leftarrow \mathsf{Encap}_\lambda(pk_R;\rho,aux),\;
\hat e \leftarrow \mathsf{CanonEncap}_\lambda(pk_R,e,aux)
\Big]
\ge 1-\mathrm{negl}(\lambda).
]

For the cover branch,
[
\Pr\Big[
\hat e^\$ \in \widehat{\mathcal{E}}^{adm}_\lambda(pk_R,aux)
\;:\;
e^\$ \leftarrow \mathcal{D}^{cover}_{\lambda,aux}(pk_R),\;
\hat e^\$ \leftarrow \mathsf{CanonEncap}_\lambda(pk_R,e^\$,aux)
\Big]
\ge 1-\mathrm{negl}(\lambda).
]

These support-alignment conditions are mandatory. Without them, malformed-vs-valid challenge behavior can become a trivial distinguisher.

**Note.** The support alignment condition for the cover branch is a consequence of CovDist-Compat (§2a.1): if the cover marginal is computationally indistinguishable from the real encapsulation marginal, and the real encapsulation is in `\widehat{\mathcal{E}}^{adm}` with overwhelming probability, then so is the cover draw. An instantiation satisfying CovDist-Compat therefore gets cover-branch support alignment without additional argument.

#### 5.2 Named bad events

In the CCA setting, define the challenge support failure event
[
\mathsf{Bad}^{supp}
\iff
\hat e^* \notin \widehat{\mathcal{E}}^{adm}_\lambda(pk_R,aux),
]
where `\hat e^* := \mathsf{CanonEncap}_\lambda(pk_R,e^*,aux)`.

Define the pre-challenge canonical-collision event
[
\mathsf{Bad}^{pre\text{-}can}
\iff
\exists e \in \mathcal{Q}^{pre}_{dec}
\text{ such that }
\mathsf{CanonEncap}_\lambda(pk_R,e,aux)=\hat e^*
\in \widehat{\mathcal{E}}^{adm}_\lambda(pk_R,aux),
]
where `\mathcal{Q}^{pre}_{dec}` is the multiset of pre-challenge decapsulation queries made by the adversary.

#### 5.3 Strengthened support-aligned analysis form

## Assumption A3.3. Support-Aligned Canonical CCA Form (`qNS-IND-CCA+`)

The strengthened analysis form is the same experiment as `qNS-IND-CCA`, but with the two bad events above tracked explicitly.

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA+}_{\mathcal A}(\lambda,q_{dec})
:=
\left|
\Pr[b'=b \land \neg \mathsf{Bad}^{supp} \land \neg \mathsf{Bad}^{pre\text{-}can}]
-
\Pr[b'\neq b \land \neg \mathsf{Bad}^{supp} \land \neg \mathsf{Bad}^{pre\text{-}can}]
\right|.
]

This strengthened form is the assumption-friendly object a later theorem can actually compose with.

#### 5.4 Explicit accounting hook

Later proofs may charge the bad events explicitly via the decomposition
[
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA}_{\mathcal A}(\lambda,q_{dec})
\le
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA+}_{\mathcal A}(\lambda,q_{dec})
+
\Pr[\mathsf{Bad}^{supp}]
+
\Pr[\mathsf{Bad}^{pre\text{-}can}].
]

This is the intended accounting path for canonical-valid support mismatch and pre-challenge canonical-class collisions.

---

### 6. Multi-target strengthened variant

## Assumption A3.4. Multi-Target Support-Aligned Canonical CCA Form (`qNS-IND-CCA-MT`)

The multi-target game extends `qNS-IND-CCA+` to `N` recipient public keys.

1. sample
   [
   aux \leftarrow \mathsf{Setup}_\lambda,
   \qquad
   (pk_i,sk_i)\leftarrow \mathsf{KeyGenEnc}_\lambda(aux)
   \text{ for } i\in[N],
   ]
2. give `((pk_i)_{i=1}^N,aux)` to the adversary,
3. give oracle access to all decapsulation oracles
   [
   \mathcal{O}^{dec}_{sk_i}(\cdot)
   \text{ for } i\in[N],
   ]
   with total query budget `q_{dec}`,
4. after arbitrary pre-challenge interaction, let the adversary output a target index `i^* \in [N]`,
5. sample the challenge bit `b` and challenge pair `(e^*,K^*)` for `pk_{i^*}` exactly as in `qNS-IND`,
6. define
   [
   \hat e^* := \mathsf{CanonEncap}_\lambda(pk_{i^*},e^*,aux),
   ]
   together with the target-specific bad events
   [
   \mathsf{Bad}^{supp}_{i^*}
   \iff
   \hat e^* \notin \widehat{\mathcal{E}}^{adm}_\lambda(pk_{i^*},aux),
   ]
   and
   [
   \mathsf{Bad}^{pre\text{-}can}_{i^*}
   \iff
   \exists e \in \mathcal{Q}^{pre}_{dec}(i^*)
   \text{ such that }
   \mathsf{CanonEncap}_\lambda(pk_{i^*},e,aux)=\hat e^*
   \in \widehat{\mathcal{E}}^{adm}_\lambda(pk_{i^*},aux),
   ]
   where `\mathcal{Q}^{pre}_{dec}(i^*)` is the multiset of pre-challenge decapsulation queries made to the target oracle,
7. give `(i^*,e^*,K^*)` to the adversary,
8. allow post-challenge oracle queries to all recipient oracles, except that the target oracle for `i^*` returns `\mathsf{forbidden}` on the canonical challenge class,
9. let `b'` be the adversary's output bit.

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA\text{-}MT}_{\mathcal A}(\lambda,N,q_{dec})
:=
\left|
\Pr[b'=b \land \neg \mathsf{Bad}^{supp}_{i^*} \land \neg \mathsf{Bad}^{pre\text{-}can}_{i^*}]
-
\Pr[b'\neq b \land \neg \mathsf{Bad}^{supp}_{i^*} \land \neg \mathsf{Bad}^{pre\text{-}can}_{i^*}]
\right|.
]

The multi-target form is the version a real signcryption proof should expect to pay against, not the single-recipient fairy tale.

#### 6.1 Adaptive target selection and reduction loss

**[FIX-A3-2]** The adversary in A3.4 selects the target index `i^*` adaptively, after seeing all `N` public keys and conducting arbitrary pre-challenge oracle queries to all `N` decapsulation oracles. This is intentionally the strongest formulation.

However, any reduction from A3.4 to the single-target game (A3.3) must pay an **explicit factor of `N`** in the reduction loss. The standard hybrid argument gives:

[
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA\text{-}MT}_{\mathcal A}(\lambda,N,q_{dec})
\le
N \cdot \mathrm{Adv}^{qNS\text{-}IND\text{-}CCA+}_{\mathcal B}(\lambda,q_{dec})
]

for some QPT reduction `\mathcal{B}` with comparable query budget. This `N`-factor loss is unavoidable in the adaptive-target-selection setting without additional structural assumptions.

**Consequence for parameter selection.** Any concrete instantiation that claims `\lambda`-bit post-quantum security in the multi-target setting must target at least `\lambda + \log_2 N` bits of single-target advantage bound, or equivalently must ensure

[
\mathrm{Adv}^{qNS\text{-}IND\text{-}CCA+}_{\mathcal B}(\lambda,q_{dec}) \le 2^{-\lambda - \log_2 N}.
]

This cost must be accounted for explicitly. It cannot be absorbed into the negligible function.

**Committed-target variant.** If the proof context permits requiring the adversary to commit to `i^*` before any pre-challenge oracle queries, the adaptive target-selection advantage is eliminated and the `N`-factor loss does not apply. In that setting the committed-target variant game applies:

* Step 4 of the A3.4 game is moved to before Step 3,
* and the adversary must declare `i^*` before querying any decapsulation oracle.

The committed-target variant is strictly weaker than A3.4 for the adversary and correspondingly easier to reduce from. If a proof can be structured to use the committed-target form, it avoids the `N`-factor loss at the cost of a slightly less adversarially generous model.

---

### 7. Domain separation as a structural obligation

**[FIX-A3-3]** The derived-randomness note in the original document (§7) correctly identified a domain-separation obligation but left it as a casual remark. Given the severity of the attack enabled by domain-separation failure — namely, a distinguisher that exploits shared structure across derived randomness streams — this obligation is elevated here to a named structural requirement.

**Definition (Domain-Separated Derivation).** An encapsulation randomness derivation scheme `\mathsf{DeriveRand}` satisfies **domain-separated derivation** if:

1. **Deterministic derivation from root seed**: for any root seed `\sigma`, the derived randomness streams `\rho_1, \rho_2, \ldots` are deterministic functions of `(\sigma, \mathsf{label}_1), (\sigma, \mathsf{label}_2), \ldots` respectively, where the labels are distinct for distinct roles, parties, and protocol instances.

2. **Pseudorandom separation**: to any party not holding the root seed `\sigma`, the derived streams `(\rho_1, \rho_2, \ldots)` are computationally indistinguishable from independent uniform random strings, under the relevant PRF or PRG assumption.

3. **Label collision freedom**: label strings must be designed so that no two distinct derivation contexts produce the same label. The label space must include at minimum: role identifier, session identifier, party identifier, and protocol version tag.

This is an **instantiation-layer structural obligation**. Violation of domain-separated derivation is not a failure of A3 as a family assumption; it is a design failure at the instantiation layer that may create a distinguisher appearing to falsify A3 in that instantiation.

Any instantiation using derived encapsulation randomness must include an explicit domain-separation argument. The argument must address all three conditions above.

---

### 8. External primitive assumptions

This custom-family assumption does **not** absorb the full burden of:

* hash or KDF security,
* random-oracle or QROM behavior,
* extractor arguments for later symmetric-key derivation,
* or concrete side-channel defenses.

Those belong to the later instantiation and theorem layer.

The role of A3 is narrower and cleaner:

* real HICS encapsulations must computationally blend into the native public shell language while carrying a recoverable key,
* subject to the CovDist-Compat requirement (§2a) making the cover distribution non-trivially specified.

---

### 9. Intended role

A3 is intended to support:

* the confidentiality game hop for the public encapsulation shell,
* outsider indistinguishability of real encapsulations from native cover shells,
* and the later derivation of symmetric secrecy from a recoverable encapsulated key.

---

### 10. What A3 does not claim

A3 does **not** by itself imply:

* semantic transcript binding,
* authenticity,
* full signcryption non-malleability,
* or the correctness of any external KDF, random-oracle, or QROM argument layered on top of the encapsulated key.