# CoreC5.md

## Global Design Invariants and Admissibility Discipline for HICS-v1

### 1. Purpose

This document records the **global invariants** that every later algorithm, proof, and reduction built over HICS-v1 must obey.

Its purpose is to stop later sections from quietly mutating the design until the assumptions and the scheme no longer describe the same object.

This file is the law book, not the marketing deck.

---

### 2. Object hierarchy

HICS-v1 contains the following layers:

1. **hidden witness layer**
   [
   x = (S,I,C,\alpha,\pi,\omega)
   ]

2. **public projection layer**
   [
   Y = (Y_S,Y_I,Y_C,Y_A,Y_{tag})
   ]

3. **commitment layer**
   [
   W \in \mathcal{W}_\lambda
   ]

4. **encapsulation layer**
   [
   encap \in \mathcal{E}_\lambda
   ]

5. **transcript layer**
   [
   m \in \mathcal{M}_\lambda
   ]

6. **binding layer**
   [
   B = \mathsf{Bind}_\lambda(Y,m,aux)
   ]

These layers must remain conceptually distinct, even if later implementations optimize them internally.

---

### 3. Admissibility discipline

The following objects are admissible iff they satisfy their designated predicates or syntax rules:

* admissible witness:
  [
  x \in \mathcal{X}^{adm}*\lambda(aux)
  \iff \mathsf{ValidWit}*\lambda(x,aux)=1
  ]

* admissible projection:
  [
  Y \in \mathcal{Y}^{adm}_\lambda(aux)
  ]

* admissible transcript:
  [
  m \in \mathcal{M}^{adm}_\lambda(aux)
  ]

* admissible encapsulation:
  [
  encap \in \mathcal{E}^{adm}_\lambda(aux)
  ]

Later algorithms may reject malformed objects, but may not silently reinterpret them as alternate valid encodings.

---

### 4. Domain-separation invariant

HICS-v1 uses a master ephemeral root seed
[
S_{root} \leftarrow {0,1}^{256}
]
and domain-separated derived sub-seeds
[
S_{wit},; S_{com},; S_{enc},; S_{sym}.
]

The system must ensure that, conditioned on (S_{root}), these sub-seeds govern distinct cryptographic roles.

#### Forbidden coupling

No public confidentiality object may be a deterministic function of:

* live authenticity-side witness state,
* commitment mask state,
* or any simulator-sensitive signing-internal state.

This is a theorem-survival rule, not a matter of aesthetic taste.

---

### 5. Information exposure invariant

The projection (Y) may reveal only:

* support block counts,
* incidence-class counts,
* constraint-class counts,
* coarse assignment statistics,
* and domain tags.

It must not reveal:

* exact support membership,
* exact active hyperedges,
* exact planted-core locations,
* exact assignment placement,
* exact embedding (\pi),
* exact slack/noise structure.

Similarly:

* the commitment object must not become a direct witness leak,
* the encapsulation object must not reveal recovered receiver-side secret state,
* and the transcript must expose only what is intentionally public and bound.

---

### 6. Binding invariant

Every security-relevant transcript field must be covered by the binding object.

No field may influence verification semantics while remaining outside the bound public object.

Canonical encoding is mandatory.

If later files violate that, they are not refining HICS-v1. They are mutating it.

---

### 7. Many-to-one invariant

Later refinements may not refine the public projection so far that the many-to-one geometry collapses into near injectivity.

In particular, later files may not publish:

* exact support coordinates,
* exact hyperedge identities,
* exact planted-core positions,
* exact assignment placement,

unless the assumption stack is correspondingly rewritten.

---

### 8. Cover-distribution invariant

Any future encapsulation shell must live inside, or be computationally close to, a **natural public shell language** already native to HICS-v1.

No artificial cover distribution may be invented later merely to rescue A3 on paper.

If the shell does not blend naturally, the design is wrong.

---

### 9. Non-goals

HICS-v1 is **not** allowed to drift toward:

* hidden algebraic structure adopted for convenience,
* proof-by-naming,
* ambiguous parser-level equivalences,
* cross-role state reuse masquerading as elegance.

Those are anti-goals.

---

### 10. Threat-model invariants

Later design work must keep HICS-v1 aimed against:

* support reconstruction,
* incidence reconstruction,
* planted-core extraction,
* alternate-witness search,
* semantic transcript equivocation,
* encapsulation-shell distinguishers,
* malformed-object ambiguity,
* Grover-amplified witness search,
* quantum-walk improvements,
* and hidden-structure exploitation from accidental symmetry.

---

### 11. Dependency map

The core dependencies are:

* A1 depends on many-to-one projection geometry and hidden-structure loss,
* A2 depends on canonical transcript binding and admissible projection discipline,
* A3 depends on a natural encapsulation shell language and strict randomness separation.

The final signcryption theorem depends on all three plus the symmetric layer and later concrete algorithms.

---

### 12. Role of CoreC5

`CoreC5` freezes the invariants of the HICS-v1 core before later algorithms are built.

It is the final core document needed before the assessment phase.