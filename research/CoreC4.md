# CoreC4.md

## Concrete Witness and Projection Language for HICS-v1

### 1. Purpose

This document defines the first concrete witness language and public projection language for the HICS family, denoted **HICS-v1**.

It fixes:

* the witness syntax,
* the public projection syntax,
* the admissible public projection space,
* the concrete loss geometry of the projection,
* the public parameter regime,
* and the witness-generation law.

This is the first point where the module base becomes mathematically specific enough to attack.

---

### 2. Global public universe

Let
[
\mathcal{U}_\lambda = (V,\mathcal{H},\Sigma,\Gamma)
]
where:

* (V) is the public vertex set,
* (\mathcal{H}) is the family of admissible bounded-arity hyperedges,
* (\Sigma) is the finite label alphabet,
* (\Gamma) is the family of local constraint templates.

The public auxiliary context `aux` includes all globally fixed parameters and admissibility rules.

---

### 3. Public parameter regime

For security parameter (\lambda), define:

* (n = |V|), the public vertex count,
* (k), the hidden support size,
* (m), the hidden active hyperedge count,
* (q_c), the planted constraint count,
* (d_h), the maximum hyperedge arity,
* (\Delta), the public degree bound,
* (b), the number of public blocks,
* (|\Sigma|=s), the symbol-alphabet size.

These parameters must satisfy the following asymptotic regime:

#### 3.1 Growth regime

[
n = poly(\lambda), \qquad
b = polylog(n)\ \text{or}\ n^\beta\ \text{for some fixed } 0<\beta<1,
]
[
k = \Theta(n^\alpha)\ \text{for some fixed } 0<\alpha<1,
]
[
m = \Theta(k), \qquad
q_c = \Theta(k), \qquad
d_h = O(1), \qquad
\Delta = O(1), \qquad
s = O(1)\ \text{or}\ polylog(n).
]

#### 3.2 Intended effect

This regime is chosen so that:

* the hidden witness remains sparse,
* the support is much smaller than the ambient universe,
* the planted core remains local,
* block-count projections remain lossy,
* and the number of witnesses consistent with a typical projection remains plausibly super-polynomial.

This is not yet a hardness theorem. It is the parameter discipline needed before one can even try to prove one.

---

### 4. Witness syntax

A witness is
[
x = (S, I, C, \alpha, \pi, \omega)
]
where:

* (S \subseteq V), (|S|=k), is the hidden support,
* (I \subseteq \mathcal{H}(S)), (|I|=m), is the hidden active hyperedge family,
* (C) is the planted local constraint core,
* (\alpha : S \to \Sigma) is the hidden assignment,
* (\pi) is the private embedding/permutation operator,
* (\omega) is hidden masking/slack state.

---

### 5. Local constraint language

The initial HICS-v1 local constraint language contains three primitive template families:

1. **Guarded equality**
   requiring selected local labels to match,

2. **Guarded inequality**
   requiring selected local labels to differ,

3. **Pattern membership**
   requiring a local tuple of labels to lie in an allowed finite pattern set.

These templates are chosen to remain explicitly combinatorial rather than algebraically expressive.

### 5.1 Design note on expressiveness

This language is intentionally conservative. It is strong enough to define a planted local consistency structure, but weak enough to avoid obvious algebraicization. Its eventual adequacy for A1 depends on the parameter regime and on the density/locality of the planted core. That must be analyzed explicitly later; it is not assumed for free.

---

### 6. Witness validity

The witness-validity predicate
[
\mathsf{ValidWit}_\lambda(x,aux)
]
holds iff:

* (S) is a support set of size (k),
* (I) is a valid sparse active hyperedge set over (S),
* all vertex degrees obey the public bound (\Delta),
* every constraint in (C) is local to the induced incidence structure,
* the hidden assignment (\alpha) satisfies all constraints in (C),
* the embedding/permutation (\pi) is admissible,
* and the slack state (\omega) obeys the public masking budget.

This predicate is efficiently computable.

---

### 7. Explicit witness-generation law

Define
[
x \leftarrow \mathsf{GenWit}*\lambda(aux; \sigma*{wit})
]
by the following planted-distribution process.

#### Step 1: support sampling

Sample (S \subseteq V) uniformly from all (k)-subsets of (V).

#### Step 2: hidden incidence sampling

Let (\mathcal{H}(S)) be the admissible hyperedges fully supported on (S). Sample (I) uniformly, or from a publicly specified bounded-degree sparse distribution, among size-(m) subsets of (\mathcal{H}(S)) satisfying the degree bound (\Delta).

#### Step 3: hidden assignment sampling

Sample
[
\alpha : S \to \Sigma
]
uniformly from (\Sigma^S), or from a publicly specified product distribution over (\Sigma).

#### Step 4: planted constraint-core sampling

Sample (q_c) local constraints by:

* choosing a local support hyperedge or constant-radius neighborhood inside (I),
* choosing a template from (\Gamma),
* retaining only constraints satisfied by (\alpha).

Equivalently, (C) is sampled from the conditional distribution of admissible local constraints satisfied by (\alpha) on (I).

#### Step 5: embedding/permutation sampling

Sample (\pi) uniformly from the allowed embedding/permutation family (\Pi_\lambda(aux)).

#### Step 6: masking/slack sampling

Sample (\omega) from a publicly specified masking/noise law (\Omega_\lambda(aux)).

### 7.1 Explicit-law requirement

Every one of the six steps above must remain explicitly specified in any later refinement. Later algorithm files may optimize the sampler, but may not replace it with “sample somehow.” That phrase should be treated as a controlled substance.

### 7.2 Seed-injectable form

The sampler must admit deterministic coin injection:
[
\sigma_{wit} = \mathsf{KDF}(S_{root}, \texttt{"WIT"}, aux).
]

---

### 8. Public block system

The vertex set (V) is partitioned into public blocks:
[
\mathcal{B} = {B_1,\dots,B_b}.
]

This partition is public and fixed by `aux`.

The purpose of the block system is to define the first layer of projection loss: the support is not revealed exactly, only through coarse blockwise statistics.

---

### 9. Hyperedge classes

The admissible hyperedge family (\mathcal{H}) is partitioned into public hyperedge classes
[
\mathcal{T}_H = {T_1,\dots,T_r},
]
grouped by:

* arity,
* public block footprint,
* and public hyperedge-type tags.

This supports coarse incidence projection without revealing exact hidden hyperedges.

---

### 10. Constraint locality classes

The planted local constraints are partitioned into public classes
[
\mathcal{T}_C = {C_1,\dots,C_s},
]
grouped by:

* constraint template type,
* locality radius,
* public block footprint,
* and neighborhood class.

This supports a public constraint shell without exposing the planted core itself.

---

### 11. Public projection

The public projection is
[
Y = \mathsf{Proj}*\lambda(x,aux)
= (Y_S, Y_I, Y_C, Y_A, Y*{tag})
]
with the following components.

#### 11.1 Support shadow

[
Y_S = (s_1,\dots,s_b),
\qquad s_j = |S \cap B_j|.
]

#### 11.2 Incidence shadow

[
Y_I = (i_1,\dots,i_r),
\qquad i_\ell = |{h \in I : \mathrm{class}(h)=T_\ell}|.
]

#### 11.3 Constraint shell

[
Y_C = (c_1,\dots,c_s),
\qquad c_j = |{(\gamma,h)\in C : \mathrm{class}(\gamma,h)=C_j}|.
]

#### 11.4 Assignment shadow

[
Y_A = (a_1,\dots,a_{|\Sigma|}),
\qquad a_u = |{v \in S : \alpha(v)=\sigma_u}|.
]

#### 11.5 Tag field

[
Y_{tag} = (\texttt{HICS-v1}, \texttt{domain}, \texttt{role}, \texttt{ctx-tag}, \texttt{version}).
]

---

### 12. Admissible public projections

Define (\mathcal{Y}^{adm}*\lambda(aux)) as the set of tuples
[
(Y_S,Y_I,Y_C,Y_A,Y*{tag})
]
satisfying:

* support-count consistency,
* incidence-count consistency,
* constraint-count consistency,
* assignment-histogram consistency,
* coarse feasibility between support, incidence, and constraint counts,
* and tag consistency with `aux`.

This admissible set is intentionally broader than the image of honest witness generation.

---

### 13. Many-to-one geometry

The HICS-v1 projection is many-to-one by design because it discards:

* exact support membership,
* exact active hyperedge identities,
* exact local constraint placement,
* exact assignment placement,
* exact private embedding,
* exact slack structure.

Different witnesses can therefore induce the same support shadow, incidence-class counts, constraint-class counts, assignment histogram, and tag field.

This is the intended geometry supporting A1.

---

### 14. Preimage-size and hardness note

At this stage, `CoreC4` defines a projection language and a planted witness distribution. It does **not yet** prove that:

* the valid preimage set above a typical projection is super-polynomial, or
* recovering a witness from that projection is computationally hard.

Those are separate obligations for the later hardness-assessment phase.

However, the current design is explicitly parameterized so that such claims are at least plausible:

* sparse hidden support,
* lossy blockwise projection,
* class-count incidence summaries,
* planted local constraints,
* and hidden assignment placement.

The future assessment must address both:

1. **preimage multiplicity**, and
2. **reconstruction hardness**.

Those are related but not the same. Humans keep conflating them because both sound hard from across the room.

---

### 15. Semantic compatibility

The projection language is designed so that later transcript binding can treat (Y) as a canonical public object. This gives A2 a concrete target.

The projection language is also intended to provide a native statistical shell that future encapsulation objects may blend into, giving A3 a concrete public-language target.

---

### 16. Role of CoreC4

`CoreC4` is the first mathematically specific core file. It defines the concrete witness and projection language for HICS-v1, together with the first explicit witness-generation law and the first explicit parameter regime.
