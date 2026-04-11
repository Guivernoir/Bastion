# A2 Basis Document

## Structural Binding Basis for HICS (Hybrid Incidence-Constraint Systems) Signcryption

### 1. Purpose

This file records the **binding basis** that the HICS design must satisfy in order for a later proof to derive semantic projection binding.

It is intentionally no longer a base custom-family hardness assumption.

The job of this document is to make explicit:

* what must be encoded canonically,
* what semantics must be covered by the bound object,
* what admissibility discipline is mandatory,
* what external primitive assumptions remain,
* and what **derived binding theorems** the later proof must actually establish.

If these obligations fail, the problem is structural or cryptographic engineering. It is not something to be dignified as a mysterious new post-quantum hardness assumption.

---

### 2. Why A2 is no longer a base family assumption

The earlier A2 draft mixed together three different kinds of claims:

1. parser and canonicalization discipline,
2. coverage of security-relevant semantics by the bound transcript,
3. the cryptographic collision resistance of the concrete binding primitive.

Only the third item is genuinely cryptographic, and even that is usually an **external instantiation assumption**, not a HICS-family hardness statement.

Accordingly, A2 is now treated as:

* a **structural basis document**, and
* the place where the required derived theorems are written down cleanly.

The irreducible HICS-family assumptions remain A1 and A3.

---

### 3. Objects

Let:

* `\mathcal{Y}_\lambda`: public projection space,
* `\mathcal{M}_\lambda`: transcript-object space,
* `\mathcal{S}_\lambda`: semantic-meaning space,
* `\mathcal{B}_\lambda`: binding-object space,
* `\mathcal{AUX}_\lambda`: public auxiliary-context space.

The relevant public algorithms and predicates are:

* `\mathsf{Setup}_\lambda`,
* `\mathsf{ValidProj}_\lambda : \mathcal{Y}_\lambda \times \mathcal{AUX}_\lambda \to \{0,1\}`,
* `\mathsf{ValidMsg}_\lambda : \mathcal{M}_\lambda \times \mathcal{AUX}_\lambda \to \{0,1\}`,
* `\mathsf{EncodeProj}_\lambda : \mathcal{Y}_\lambda \times \mathcal{AUX}_\lambda \to \{0,1\}^*`,
* `\mathsf{EncodeMsg}_\lambda : \mathcal{M}_\lambda \times \mathcal{AUX}_\lambda \to \{0,1\}^*`,
* `\mathsf{Sem}_\lambda : \mathcal{M}_\lambda \times \mathcal{AUX}_\lambda \to \mathcal{S}_\lambda`,
* `\mathsf{Bind}_\lambda : \mathcal{Y}_\lambda \times \mathcal{M}_\lambda \times \mathcal{AUX}_\lambda \to \mathcal{B}_\lambda`.

The intended interpretation is:

* `Y` is the public projection,
* `m` is the structured transcript object,
* `\mathsf{Sem}_\lambda(m,aux)` is its security-relevant meaning,
* `\mathsf{Bind}_\lambda(Y,m,aux)` is the public object actually authenticated or checked by the protocol.

---

### 4. Structural obligations

For the later binding proof to be meaningful, the following obligations must hold.

#### 4.1 Canonical projection encoding

Every admissible projection must admit a unique canonical encoding:
[
\mathsf{ValidProj}_\lambda(Y,aux)=1
\implies
\mathsf{EncodeProj}_\lambda(Y,aux)
\text{ is unique and deterministic.}
]

Different admissible projections may not serialize to the same canonical byte string.

#### 4.2 Canonical transcript encoding

Every admissible semantic transcript object must admit a unique canonical encoding:
[
\mathsf{ValidMsg}_\lambda(m,aux)=1
\implies
\mathsf{EncodeMsg}_\lambda(m,aux)
\text{ is unique and deterministic.}
]

No alternate field order, omitted default, duplicate tag, ambiguous null encoding, or parser-level alias may survive admissibility.

#### 4.3 Full semantic coverage

Every field that can influence verification semantics must be inside the bound domain, including:

* encapsulation object,
* ciphertext or payload descriptor,
* associated data,
* sender and receiver context,
* protocol mode,
* version and domain tags,
* and any auxiliary context that verification actually consults.

If a field affects acceptance or meaning but sits outside the bound object, that is a design failure.

#### 4.4 Admissibility discipline

Malformed objects must not be silently reinterpreted as alternate valid ones.

In particular:

* `\mathsf{ValidProj}_\lambda` must reject malformed or non-canonical projections,
* `\mathsf{ValidMsg}_\lambda` must reject malformed or non-canonical transcript objects,
* and the semantics function `\mathsf{Sem}_\lambda` must agree with the verification semantics of the protocol.

#### 4.5 Domain-separated binding

If the same projection or transcript format may appear across roles, modes, or protocol classes, then those labels must be explicitly included in the canonical bound domain.

Cross-role ambiguity is a structural bug, not an advanced attack.

#### 4.6 Efficient deterministic binder

The public binding algorithm
[
\mathsf{Bind}_\lambda(Y,m,aux)
]
must be deterministic and efficiently computable on admissible inputs.

#### 4.7 Efficient computable and decidable semantics

**[FIX-A2-1]** The semantics function `\mathsf{Sem}_\lambda` must satisfy three conditions:

1. **Efficient computability**: `\mathsf{Sem}_\lambda(m,aux)` must be computable in polynomial time on admissible inputs `(m,aux)`.

2. **Semantic decidability**: semantic equality must be efficiently decidable. That is, given two admissible transcript objects `m_1, m_2` and `aux`, it must be possible to decide
[
\mathsf{Sem}_\lambda(m_1,aux) = \mathsf{Sem}_\lambda(m_2,aux)
]
in polynomial time.

3. **Verification alignment**: the output of `\mathsf{Sem}_\lambda(m,aux)` must agree exactly with the protocol's actual verification semantics. If two transcripts are semantically distinct under `\mathsf{Sem}_\lambda` but accepted as equivalent by the verifier, the binding theorem A2.1 is vacuous. If two transcripts are semantically equivalent under `\mathsf{Sem}_\lambda` but produce distinct verification outcomes, the binding game is ill-specified.

The verification alignment condition must be justified explicitly in any instantiation. It cannot be taken for granted by inspection.

#### 4.8 Binding collision regime

**[FIX-A2-2]** The concrete binding algorithm `\mathsf{Bind}_\lambda` must be instantiated with an explicit statement of the collision-resistance regime it relies on, chosen from:

* **Collision resistance (CR)**: no QPT adversary can find any two admissible inputs `(Y,m_1)` and `(Y,m_2)` with `m_1 \neq m_2` such that `\mathsf{Bind}_\lambda(Y,m_1,aux) = \mathsf{Bind}_\lambda(Y,m_2,aux)`.
* **Target collision resistance (TCR)**: given a uniformly random target `(Y,m_1,aux)`, no QPT adversary can find `m_2 \neq m_1` such that `\mathsf{Bind}_\lambda(Y,m_1,aux) = \mathsf{Bind}_\lambda(Y,m_2,aux)`.
* **Second-preimage resistance (SPR)**: given a fixed `(Y,m_1,aux)`, no QPT adversary can find `m_2 \neq m_1` such that `\mathsf{Bind}_\lambda(Y,m_1,aux) = \mathsf{Bind}_\lambda(Y,m_2,aux)`.

These regimes are ordered CR `\implies` TCR `\implies` SPR in terms of strength of assumption required. For a QPT adversary against a lattice-based binder, they carry distinct parameter implications and should not be conflated.

The required regime must be stated explicitly in the instantiation document. The derived binding theorem A2.1 is proved from one of these regimes plus the structural obligations above.

---

### 5. External and derived prerequisites

The later proof may invoke the following **external instantiation hypotheses**, none of which are treated here as custom HICS-family hardness assumptions:

* collision or target-collision resistance of the chosen binder on canonical inputs, in the regime specified by §4.8,
* binding completeness of the concrete transcript-commitment mechanism,
* exact agreement between `\mathsf{Sem}_\lambda` and the protocol's true verification semantics (as required by §4.7.3),
* and any required random-oracle or QROM assumptions for the concrete hashing layer.

These hypotheses are separate from the structural obligations of Section 4 and must be stated explicitly whenever a derived theorem is written.

---

### 6. Required derived binding theorems

Under:

* the structural obligations of Section 4, and
* the external instantiation hypotheses of Section 5,

the later proof must derive the following statements.

#### 6.1 Single-projection binding

## Required Derived Theorem A2.1. Semantic projection binding over adversarially chosen admissible projections

For every QPT adversary `\mathcal{A}`, there exists a negligible function `\mu(\lambda)` such that
[
\Pr\Big[
\mathsf{ValidProj}_\lambda(Y,aux)=1
\land
\mathsf{ValidMsg}_\lambda(m_1,aux)=1
\land
\mathsf{ValidMsg}_\lambda(m_2,aux)=1
\land
\mathsf{Sem}_\lambda(m_1,aux)\neq \mathsf{Sem}_\lambda(m_2,aux)
\land
\mathsf{Bind}_\lambda(Y,m_1,aux)=\mathsf{Bind}_\lambda(Y,m_2,aux)
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
(Y,m_1,m_2)\leftarrow \mathcal{A}(aux)
\Big]
\le \mu(\lambda).
]

The important point is the quantification:

* the adversary chooses `Y`,
* subject only to admissibility,
* so the target is genuinely worst-case over admissible projections.

There is no distributional loophole here: admissibility is the only gate on `Y`.

#### 6.2 Multi-projection binding

**[FIX-A2-3]** Because signcryption is inherently a multi-user, multi-target setting (per the global note §4), the single-projection form of Theorem A2.1 is insufficient for a full signcryption proof. The later proof must additionally derive the following multi-projection form.

## Required Derived Theorem A2.2. Multi-projection semantic binding (`MT-Bind`)

Let `N` be the number of distinct public projections in play.

For every QPT adversary `\mathcal{A}`, there exists a negligible function `\mu(\lambda, N)` such that
[
\Pr\Big[
\exists\, i \in [N] :
\mathsf{ValidProj}_\lambda(Y_i,aux)=1
\land
\mathsf{ValidMsg}_\lambda(m^{(i)}_1,aux)=1
\land
\mathsf{ValidMsg}_\lambda(m^{(i)}_2,aux)=1
\land
\mathsf{Sem}_\lambda(m^{(i)}_1,aux)\neq \mathsf{Sem}_\lambda(m^{(i)}_2,aux)
\land
\mathsf{Bind}_\lambda(Y_i,m^{(i)}_1,aux)=\mathsf{Bind}_\lambda(Y_i,m^{(i)}_2,aux)
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
((Y_i, m^{(i)}_1, m^{(i)}_2)_{i=1}^N)\leftarrow \mathcal{A}(aux)
\Big]
\le \mu(\lambda, N).
]

The expected form of `\mu(\lambda, N)` via a union-bound reduction from Theorem A2.1 is:
[
\mu(\lambda,N) \le N \cdot \mu_1(\lambda),
]
where `\mu_1(\lambda)` is the negligible function from the single-projection form. This linear loss in `N` must be carried explicitly; it cannot be silently absorbed.

If the concrete binding primitive is a random oracle or a structured hash, tighter multi-projection bounds may be available from the concrete analysis, but they must be stated and proved, not assumed.

**Remark.** The multi-projection form is a **required derived statement**, not a base HICS-family assumption. Its proof structure follows A2.1 by union bound plus the relevant external instantiation hypothesis. But if it is omitted from the later proof, the signcryption unforgeability argument has a gap.

---

### 7. What this file now means

This file still matters because it specifies the design discipline without which later A2-style proofs would be malformed or vacuous.

But it no longer tries to elevate semantic binding itself into a standalone HICS-family hardness primitive.

That move was too broad and too expensive.

The current position is cleaner:

* HICS contributes the projection structure and transcript interface,
* the design contributes canonicalization and admissibility discipline,
* the concrete instantiation contributes standard binding machinery in a named collision-resistance regime,
* and the later proof must connect them.

---

### 8. What A2 does not do

A2 does **not** by itself assert:

* witness hardness,
* encapsulation indistinguishability,
* full signcryption unforgeability,
* or any custom-family property that cannot be reduced to the structural obligations and external instantiation hypotheses above.