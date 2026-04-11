# Assumption Document A1

## QPT Hidden-Witness Search Hardness

### 1. Purpose

This document defines the first irreducible custom-family assumption in the HICS (Hybrid Incidence-Constraint Systems) stack:

> from a public projection, together with the admissible public artifacts that a signcryption adversary may observe under the same hidden state, a QPT adversary cannot efficiently recover a valid hidden witness or a distinct alternate witness.

This is the hidden-structure search root for the signcryption-side authenticity story and for any claim that public HICS projections do not already give the game away.

---

### 2. Objects and base single-instance interface

Let `\lambda` be the security parameter.

We define:

* `\mathcal{X}_\lambda`: witness space,
* `\mathcal{Y}_\lambda`: public projection space,
* `\mathcal{V}^{com}_\lambda`: commitment-facing public-artifact space,
* `\mathcal{V}^{tr}_\lambda`: transcript-facing public-artifact space,
* `\mathcal{Q}^{com}_\lambda`: admissible public queries for commitment-facing artifacts,
* `\mathcal{Q}^{tr}_\lambda`: admissible public queries for transcript-facing artifacts,
* `\mathcal{AUX}_\lambda`: public auxiliary-context space.

The public algorithms are:

* `\mathsf{Setup}_\lambda`,
* `\mathsf{GenWit}_\lambda`,
* `\mathsf{Proj}_\lambda : \mathcal{X}_\lambda \times \mathcal{AUX}_\lambda \to \mathcal{Y}_\lambda`,
* `\mathsf{ValidWit}_\lambda : \mathcal{X}_\lambda \times \mathcal{AUX}_\lambda \to \{0,1\}`,
* `\mathsf{ExposeCom}_\lambda : \mathcal{X}_\lambda \times \mathcal{Y}_\lambda \times \mathcal{Q}^{com}_\lambda \times \mathcal{AUX}_\lambda \to \mathcal{V}^{com}_\lambda`,
* `\mathsf{ExposeTr}_\lambda : \mathcal{X}_\lambda \times \mathcal{Y}_\lambda \times \mathcal{Q}^{tr}_\lambda \times \mathcal{AUX}_\lambda \to \mathcal{V}^{tr}_\lambda`.

An honest single-instance challenge is sampled as:
[
aux \leftarrow \mathsf{Setup}_\lambda,
\qquad
x \leftarrow \mathsf{GenWit}_\lambda(aux),
\qquad
Y := \mathsf{Proj}_\lambda(x,aux).
]

---

### 3. Named public exposure family

The admissible public-view family for A1 is:
[
\mathfrak{O}^{pub}_{x,Y,aux}
=
(\mathcal{O}^{proj}, \mathcal{O}^{com}, \mathcal{O}^{tr}),
]
with the following meaning.

#### 3.1 Projection-facing view

`\mathcal{O}^{proj}` is the fixed challenge view:

* it returns the honest projection `Y`,
* it carries no query cost,
* and it is given to the adversary at challenge setup.

#### 3.2 Commitment-facing public oracle

For admissible public query `\eta \in \mathcal{Q}^{com}_\lambda(aux)`, define
[
\mathcal{O}^{com}_{x,Y,aux}(\eta)
:=
\mathsf{ExposeCom}_\lambda(x,Y,\eta,aux)
\in
\mathcal{V}^{com}_\lambda.
]

This oracle models public commitment anchors or analogous public objects derived from the honest hidden state.

#### 3.3 Transcript-facing public oracle

For admissible public query `\tau \in \mathcal{Q}^{tr}_\lambda(aux)`, define
[
\mathcal{O}^{tr}_{x,Y,aux}(\tau)
:=
\mathsf{ExposeTr}_\lambda(x,Y,\tau,aux)
\in
\mathcal{V}^{tr}_\lambda.
]

This oracle models transcript-facing public artifacts that may be correlated with the same honest hidden state.

#### 3.4 Public-view-only rule

The oracle family `\mathfrak{O}^{pub}` is restricted to **public-view oracles only**.

In particular, it may expose only public artifacts derivable from the honest hidden state and public query string. It may **not**:

* test candidate witnesses,
* reveal hidden-state predicates unavailable in the real protocol,
* expose secret-validation or accept/reject behavior beyond the public artifact itself,
* or smuggle in secret-oracle power under prettier notation.

#### 3.5 Query budget notation

Let:

* `q_{com}` be the number of commitment-facing queries,
* `q_{tr}` be the number of transcript-facing queries,
* `q_{pub} := q_{com} + q_{tr}` be the total public-exposure query budget.

#### 3.6 Joint oracle leakage discipline

**[FIX-A1-1]** The oracle pair `(\mathcal{O}^{com}, \mathcal{O}^{tr})` is simultaneously accessible to the adversary in the AP variants. Because both oracles are derived from the same hidden state `x`, their joint responses may carry leakage that neither oracle alone provides.

The following discipline is therefore mandatory for any concrete instantiation of A1:

**Definition (Bounded Joint Leakage).** The joint transcript
[
L^{joint}_{q_{com},q_{tr}}
:=
\Big(
(\eta_1, \mathcal{O}^{com}_{x,Y,aux}(\eta_1)), \ldots,
(\eta_{q_{com}}, \mathcal{O}^{com}_{x,Y,aux}(\eta_{q_{com}})),\;
(\tau_1, \mathcal{O}^{tr}_{x,Y,aux}(\tau_1)), \ldots,
(\tau_{q_{tr}}, \mathcal{O}^{tr}_{x,Y,aux}(\tau_{q_{tr}}))
\Big)
]
must satisfy one of two conditions:

1. **Conditional independence**: conditioned on `(Y, aux)`, the responses of `\mathcal{O}^{com}` and `\mathcal{O}^{tr}` are computationally independent. That is, there exist efficient simulators `\mathsf{Sim}^{com}_\lambda` and `\mathsf{Sim}^{tr}_\lambda` such that the joint distribution
[
(L^{joint}_{q_{com},q_{tr}} \mid Y, aux)
\approx_c
(\mathsf{Sim}^{com}_\lambda(Y,aux,q_{com}),\; \mathsf{Sim}^{tr}_\lambda(Y,aux,q_{tr}))
]
is computationally indistinguishable from the product of independently simulated transcripts; or

2. **Explicit joint leakage bound**: the mutual information `I(x\,;\, L^{joint}_{q_{com},q_{tr}} \mid Y, aux)` is bounded by an explicitly stated function of `(q_{pub}, \lambda)`, and that bound is carried through as an additive term in the advantage decomposition of all AP variants.

If neither condition is satisfied in a concrete instantiation, the AP variants (A1.3, A1.4) are not directly comparable to the base games (A1.1, A1.2), and any proof invoking them must carry the leakage gap explicitly.

This is an **instantiation-layer obligation**, not a property asserted at the family level. But the family-level games are only well-calibrated when one of the two conditions above is met.

---

### 4. Meaningfulness precondition: many-to-one geometry and witness entropy

**[FIX-A1-2]** The HICS projection must be **many-to-one enough** on the valid witness set, and the witness sampler must produce witnesses with sufficient entropy, to make witness search a nontrivial hiding problem.

#### 4.1 Min-entropy requirement on GenWit

For the witness-hiding story to be non-vacuous, the honest witness sampler must produce witnesses with sufficient unpredictability. Formally, the following min-entropy lower bound is a mandatory instantiation obligation:

[
H_\infty(x \mid aux)
\ge
\omega(\log \lambda),
]

where the min-entropy is taken over the distribution `x \leftarrow \mathsf{GenWit}_\lambda(aux)` for a uniformly random `aux \leftarrow \mathsf{Setup}_\lambda`.

For concrete parameter claims against a QPT adversary, the required bound is substantially stronger. Specifically:

* against Grover-style amplification, recovery of a witness from the uniform preimage set costs `O(2^{H_\infty/2})` quantum queries;
* accordingly, any concrete claim of `\lambda`-bit post-quantum witness-search hardness requires
[
H_\infty(x \mid aux) \ge 2\lambda.
]

The family document does not fix a concrete value. That is an instantiation obligation. But a concrete instantiation that claims post-quantum hardness while providing a witness sampler with sublinear min-entropy is not in compliance with A1.

#### 4.2 Projection entropy requirement

In addition, the projection must not collapse the witness distribution to a small support. Formally:

[
H_\infty(Y \mid aux)
\ge
\omega(\log \lambda),
]

where `Y := \mathsf{Proj}_\lambda(x, aux)` and the min-entropy is over honest sampling.

This prevents the trivial attack where the adversary enumerates the (polynomially small) range of `\mathsf{Proj}` and works backwards.

#### 4.3 Preimage multiplicity

For a non-negligible fraction of honestly generated projections `Y`, the valid preimage set
[
\mathrm{Pre}_\lambda(Y;aux)
:=
\{x' \in \mathcal{X}_\lambda :
\mathsf{ValidWit}_\lambda(x',aux)=1
\land
\mathsf{Proj}_\lambda(x',aux)=Y\}
]
must be super-polynomially large, unless a later concrete instantiation explicitly narrows the claim.

#### 4.4 Status of these conditions

The entropy and multiplicity conditions in §§4.1–4.3 are **mandatory credibility preconditions** for a concrete instantiation.

They do **not** by themselves prove:

* recovery hardness,
* alternate-witness hardness,
* or any implication between the base, adaptive-public-exposure, or multi-target variants below.

Sufficient entropy and preimage multiplicity make the hiding story worth discussing. They do not do the reduction work.

---

### 5. Search relation

Define the projection witness relation
[
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)=1
\iff
\mathsf{ValidWit}_\lambda(x',aux)=1
\land
\mathsf{Proj}_\lambda(x',aux)=Y.
]

---

### 6. Base single-instance games

## Assumption A1.1. QPT Hidden-Witness Search Hardness (`qHWPH`)

The base game gives the adversary only:

* `aux`,
* and the honest projection `Y`.

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qHWPH}_{\mathcal A}(\lambda)
:=
\Pr\Big[
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)=1
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
x \leftarrow \mathsf{GenWit}_\lambda(aux),\;
Y \leftarrow \mathsf{Proj}_\lambda(x,aux),\;
x' \leftarrow \mathcal{A}(Y,aux)
\Big].
]

The assumption requires
[
\mathrm{Adv}^{qHWPH}_{\mathcal A}(\lambda) \le \mathrm{negl}(\lambda).
]

### Interpretation

Given only the honest public projection, no efficient quantum adversary can recover **any** valid witness for that projection except with negligible probability.

---

## Assumption A1.2. QPT Alternate-Witness Search Hardness (`qAWH`)

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qAWH}_{\mathcal A}(\lambda)
:=
\Pr\Big[
x' \neq x
\land
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)=1
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
x \leftarrow \mathsf{GenWit}_\lambda(aux),\;
Y \leftarrow \mathsf{Proj}_\lambda(x,aux),\;
x' \leftarrow \mathcal{A}(Y,aux)
\Big].
]

The assumption requires
[
\mathrm{Adv}^{qAWH}_{\mathcal A}(\lambda) \le \mathrm{negl}(\lambda).
]

### Interpretation

Even if the original hidden witness is not recovered, no efficient quantum adversary can output a **different** valid witness mapping to the same public projection.

---

### 7. Adaptive public-exposure variants

## Assumption A1.3. Adaptive-Public-Exposure Hidden-Witness Search Hardness (`qHWPH-AP`)

The strengthened game gives the adversary:

* `aux`,
* the honest projection `Y`,
* oracle access to `\mathcal{O}^{com}_{x,Y,aux}`,
* oracle access to `\mathcal{O}^{tr}_{x,Y,aux}`,
* with total public-exposure budget `q_{pub}`.

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qHWPH\text{-}AP}_{\mathcal A}(\lambda,q_{pub})
:=
\Pr\Big[
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)=1
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
x \leftarrow \mathsf{GenWit}_\lambda(aux),\;
Y \leftarrow \mathsf{Proj}_\lambda(x,aux),\;
x' \leftarrow \mathcal{A}^{\mathcal{O}^{com}_{x,Y,aux},\mathcal{O}^{tr}_{x,Y,aux}}(Y,aux)
\Big].
]

The assumption requires
[
\mathrm{Adv}^{qHWPH\text{-}AP}_{\mathcal A}(\lambda,q_{pub}) \le \mathrm{negl}(\lambda)
\]
for every QPT adversary making at most `q_{pub}` admissible public-exposure queries.

**Note on joint leakage.** This game is well-calibrated only when the joint oracle leakage discipline of §3.6 is satisfied by the concrete instantiation. If it is not, the advantage bound must be supplemented by an additive joint-leakage term as described there.

---

## Assumption A1.4. Adaptive-Public-Exposure Alternate-Witness Search Hardness (`qAWH-AP`)

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qAWH\text{-}AP}_{\mathcal A}(\lambda,q_{pub})
:=
\Pr\Big[
x' \neq x
\land
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)=1
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
x \leftarrow \mathsf{GenWit}_\lambda(aux),\;
Y \leftarrow \mathsf{Proj}_\lambda(x,aux),\;
x' \leftarrow \mathcal{A}^{\mathcal{O}^{com}_{x,Y,aux},\mathcal{O}^{tr}_{x,Y,aux}}(Y,aux)
\Big].
]

The assumption requires
[
\mathrm{Adv}^{qAWH\text{-}AP}_{\mathcal A}(\lambda,q_{pub}) \le \mathrm{negl}(\lambda)
\]
for every QPT adversary making at most `q_{pub}` admissible public-exposure queries.

**Note on joint leakage.** Same caveat as A1.3 applies.

---

### 8. Multi-target variants

## Assumption A1.5. Multi-Target Hidden-Witness Search Hardness (`qHWPH-MT`)

The multi-target game samples a common public context and `N` honest instances:
[
aux \leftarrow \mathsf{Setup}_\lambda,
\qquad
x_i \leftarrow \mathsf{GenWit}_\lambda(aux),
\qquad
Y_i \leftarrow \mathsf{Proj}_\lambda(x_i,aux)
\quad
\text{for } i \in [N].
]

For each target `i`, the adversary receives the public-oracle family
[
\mathfrak{O}^{pub}_{x_i,Y_i,aux}
=
(\mathcal{O}^{proj}_i,\mathcal{O}^{com}_i,\mathcal{O}^{tr}_i).
]

The adversary receives all public projections `(Y_i)_{i=1}^N`, may query all public oracles subject to total budget `q_{pub}`, and outputs a target index `i^* \in [N]` together with a witness candidate `x'`.

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qHWPH\text{-}MT}_{\mathcal A}(\lambda,N,q_{pub})
:=
\Pr\Big[
\mathcal{R}^{\mathrm{proj}}_\lambda(Y_{i^*},x';aux)=1
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
(x_i,Y_i)_{i=1}^N,\;
(i^*,x') \leftarrow
\mathcal{A}^{(\mathcal{O}^{com}_i,\mathcal{O}^{tr}_i)_{i=1}^N}((Y_i)_{i=1}^N,aux)
\Big].
]

The assumption requires
[
\mathrm{Adv}^{qHWPH\text{-}MT}_{\mathcal A}(\lambda,N,q_{pub}) \le \mathrm{negl}(\lambda)
\]
for every QPT adversary with total public-exposure budget `q_{pub}`.

---

## Assumption A1.6. Multi-Target Alternate-Witness Search Hardness (`qAWH-MT`)

For every QPT adversary `\mathcal{A}`, define
[
\mathrm{Adv}^{qAWH\text{-}MT}_{\mathcal A}(\lambda,N,q_{pub})
:=
\Pr\Big[
x' \neq x_{i^*}
\land
\mathcal{R}^{\mathrm{proj}}_\lambda(Y_{i^*},x';aux)=1
\;:\;
aux \leftarrow \mathsf{Setup}_\lambda,\;
(x_i,Y_i)_{i=1}^N,\;
(i^*,x') \leftarrow
\mathcal{A}^{(\mathcal{O}^{com}_i,\mathcal{O}^{tr}_i)_{i=1}^N}((Y_i)_{i=1}^N,aux)
\Big].
]

The assumption requires
[
\mathrm{Adv}^{qAWH\text{-}MT}_{\mathcal A}(\lambda,N,q_{pub}) \le \mathrm{negl}(\lambda)
\]
for every QPT adversary with total public-exposure budget `q_{pub}`.

If `q_{pub}=0`, the multi-target forms reduce to pure multi-instance exposure of public projections.

---

### 9. Variant semantics note

Exact planted-witness recovery,
[
x' = x,
]
any-valid-witness recovery,
[
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)=1,
]
and alternate-witness search,
[
x' \neq x
\land
\mathcal{R}^{\mathrm{proj}}_\lambda(Y,x';aux)=1,
]
are distinct search tasks.

Likewise:

* the base games,
* the adaptive-public-exposure variants,
* and the multi-target variants

are distinct assumption forms.

No information-theoretic implication between them is claimed here from preimage multiplicity or entropy alone.

---

### 10. Structural requirements

For A1 to be meaningful in a concrete HICS instantiation, the following must hold.

#### 10.1 Efficient public algorithms

The algorithms
[
\mathsf{Proj}_\lambda,
\qquad
\mathsf{ValidWit}_\lambda,
\qquad
\mathsf{ExposeCom}_\lambda,
\qquad
\mathsf{ExposeTr}_\lambda
]
must be efficiently computable.

#### 10.2 Explicit witness sampler with entropy certificate

The honest distribution induced by `\mathsf{GenWit}_\lambda` must be explicitly specified, together with an explicit lower bound on `H_\infty(x \mid aux)` meeting the requirements of §4.1.

Statements of the form "sample a plausible hidden state somehow" are not admissible cryptographic notation. Statements of the form "sample a plausible hidden state somehow, and clearly it has enough entropy" are equally inadmissible.

#### 10.3 Public-oracle discipline

The public exposure family may include correlated public artifacts seen in the real protocol, but it may not smuggle in:

* secret-oracle power,
* witness-testing behavior,
* hidden-state predicates unavailable in the real protocol,
* or side-channel style accept/reject leakage beyond the public artifact itself.

#### 10.4 Joint oracle leakage certificate

For any instantiation that invokes the AP variants (A1.3, A1.4), the instantiation document must provide one of:

* a proof of conditional independence between `\mathcal{O}^{com}` and `\mathcal{O}^{tr}` responses given `(Y, aux)`, or
* an explicit mutual-information bound carried through the advantage decomposition.

This is a companion obligation to §10.2 and equally non-negotiable.

---

### 11. Post-quantum threat-model note

Because the adversary is QPT, parameter selection must survive the usual quantum search pressure, including:

* Grover-style amplification of brute-force structure search, halving the effective min-entropy against brute force,
* quantum walks over sparse support candidates,
* and hybrid classical/quantum pruning strategies exploiting public geometry.

The `H_\infty \ge 2\lambda` requirement of §4.1 is the direct consequence of Grover pressure. This document does not prove parameter adequacy for any concrete instantiation but makes the threat model explicit so that later concrete parameter claims cannot quietly retreat to a classical attacker without admitting it.

---

### 12. Intended role

A1 is intended to support:

* hidden-state non-recovery from public HICS artifacts,
* alternate-witness resistance in authenticity-style reductions,
* and the claim that HICS public keys and public transcript-facing artifacts do not trivialize the hidden combinatorial state.

---

### 13. What A1 does not claim

A1 does **not** by itself imply:

* semantic transcript binding,
* confidentiality,
* full signcryption unforgeability,
* or any statement about random-oracle, QROM, KDF, or side-channel behavior beyond the explicit games above.