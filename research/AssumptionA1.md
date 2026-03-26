# Assumption Document A1

## Hidden Witness Projection Hardness

### 1. Purpose

This assumption defines the **core hidden-structure search hardness** of the combinatorial module base. It formalizes the claim that a public projection reveals enough structure to support verification and protocol composition, but not enough to recover a valid hidden witness or to construct an alternate valid witness.

This is the foundational search assumption underlying hidden-state security, authenticity reductions, and leakage discipline.

---

### 2. Abstract objects

Let (\lambda) be the security parameter.

We define:

* (\mathcal{X}_\lambda): witness space,
* (\mathcal{Y}_\lambda): public projection space,
* (\mathcal{AUX}_\lambda): public auxiliary context space,
* (\mathsf{Setup}_\lambda): public-parameter generation algorithm,
* (\mathsf{GenWit}_\lambda): witness-generation algorithm,
* (\mathsf{Proj}*\lambda : \mathcal{X}*\lambda \times \mathcal{AUX}*\lambda \to \mathcal{Y}*\lambda): public projection map,
* (\mathsf{ValidWit}*\lambda : \mathcal{X}*\lambda \times \mathcal{AUX}_\lambda \to {0,1}): witness-validity predicate.

We write:
[
aux \leftarrow \mathsf{Setup}*\lambda,\qquad
x \leftarrow \mathsf{GenWit}*\lambda(aux),\qquad
Y := \mathsf{Proj}_\lambda(x,aux).
]

### 3. Design condition: many-to-one projection

The projection map (\mathsf{Proj}*\lambda) is assumed to be **many-to-one by design** on the valid-witness set:
[
\left| {x' \in \mathcal{X}*\lambda : \mathsf{ValidWit}*\lambda(x',aux)=1 \land \mathsf{Proj}*\lambda(x',aux)=Y } \right|
]
is super-polynomial in (\lambda) for a non-negligible fraction of honestly generated (Y), unless otherwise stated for a specific instantiation.

This condition is not cosmetic. If `Proj` were injective on valid witnesses, the alternate-witness form below would become vacuous and the assumption would collapse to unique preimage recovery.

---

### 4. Witness relation

Define the projection witness relation
[
\mathcal{R}^{\mathrm{proj}}*\lambda(Y,x';aux)=1
\iff
\mathsf{ValidWit}*\lambda(x',aux)=1
;\land;
\mathsf{Proj}_\lambda(x',aux)=Y.
]

A candidate witness (x') is valid for public image (Y) if it is structurally legal and projects to the same public object.

---

### 5. Final assumption statements

## Assumption A1.1. Hidden Witness Projection Hardness (HWPH)

For every probabilistic polynomial-time adversary (\mathcal{A}), there exists a negligible function (\mu(\lambda)) such that
[
\Pr\Big[
\mathcal{R}^{\mathrm{proj}}*\lambda(Y,x';aux)=1
;:;
aux \leftarrow \mathsf{Setup}*\lambda,;
x \leftarrow \mathsf{GenWit}*\lambda(aux),;
Y=\mathsf{Proj}*\lambda(x,aux),;
x' \leftarrow \mathcal{A}(Y,aux)
\Big]
\le \mu(\lambda).
]

### Interpretation

Given only the public projection (Y) and public context (aux), no efficient adversary can output **any** valid witness consistent with (Y), except with negligible probability.

This is a search assumption, not a decisional one.

---

## Assumption A1.2. Alternate Witness Hardness (AWH)

For every probabilistic polynomial-time adversary (\mathcal{A}), there exists a negligible function (\mu(\lambda)) such that
[
\Pr\Big[
x' \neq x
;\land;
\mathcal{R}^{\mathrm{proj}}*\lambda(Y,x';aux)=1
;:;
aux \leftarrow \mathsf{Setup}*\lambda,;
x \leftarrow \mathsf{GenWit}*\lambda(aux),;
Y=\mathsf{Proj}*\lambda(x,aux),;
x' \leftarrow \mathcal{A}(Y,aux)
\Big]
\le \mu(\lambda).
]

### Interpretation

Even if recovering the exact original witness were somehow avoided, the adversary still cannot produce a **different** valid witness mapping to the same projection.

---

### 6. Relationship between A1.1 and A1.2

Under the many-to-one design condition above, A1.2 is information-theoretically implied by A1.1 up to negligible statistical distance: if an adversary can output any valid witness for an honestly generated projection, the probability that it recovers the exact original witness is negligible when the valid preimage set is super-polynomially large.

We keep A1.2 explicitly because later reductions often need an alternate-witness statement directly, and forcing every proof to re-derive that implication is an unnecessary ritual of suffering.

In proofs that only need existence of an alternate witness independent of the original x, an A1.1 breaker can be used directly via the many-to-one condition, since outputting any valid witness is overwhelmingly unlikely to recover the exact original witness.

---

### 7. Required structural properties

For A1 to be meaningful, the module base must satisfy:

#### 7.1 Efficient projection

[
\mathsf{Proj}_\lambda(x,aux)
]
must be efficiently computable.

#### 7.2 Efficient verification

[
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)
]
must be efficiently testable.

#### 7.3 Nontrivial valid-witness geometry

The valid-witness space above a typical public projection must not be tiny or degenerate.

#### 7.4 Explicit sampler law

The distribution induced by (\mathsf{GenWit}_\lambda) must be explicitly specified.

---

### 8. Intended role

A1 is intended to support:

* hidden-state non-recovery from public protocol artifacts,
* leakage-resilience arguments,
* alternate-witness reductions in authenticity proofs,
* structural non-malleability of hidden combinatorial states.

---

### 9. What A1 does not claim

A1 does **not** by itself imply:

* confidentiality,
* transcript binding,
* strong unforgeability,
* ciphertext indistinguishability,
* or quantum security beyond the bare statement of the assumption itself.
