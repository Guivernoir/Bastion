# CoreC3.md

## Concrete Family Selection: Hybrid Incidence-Constraint Systems (HICS)

### 1. Purpose

This document fixes the first concrete object family selected from `CoreC2`:

[
\boxed{\text{Hybrid Incidence-Constraint Systems (HICS)}}
]

Its purpose is to specify the concrete *type* of hidden witness to be used in later files, while still leaving the exact public loss function and shell geometry to subsequent documents.

---

### 2. High-level structure

The HICS family combines two layers of hidden structure:

1. a **sparse incidence layer**, and
2. a **planted local constraint layer** over that incidence structure.

The resulting witness is a sparse structured hidden world embedded inside a larger noisy public combinatorial universe.

---

### 3. Public universe

Let
[
\mathcal{U}*\lambda = (V*\lambda, E_\lambda, \Sigma_\lambda, \Gamma_\lambda)
]
where:

* (V_\lambda): public vertex/atom set,
* (E_\lambda): admissible incidence pool,
* (\Sigma_\lambda): finite hidden label alphabet,
* (\Gamma_\lambda): admissible local constraint templates.

The exact combinatorial interpretation of these objects is fixed in `CoreC4`.

---

### 4. Hidden witness object

A HICS witness is a tuple
[
x = (\mathcal{S}, \mathcal{I}, \mathcal{C}, \alpha, \pi, \omega)
]
where:

* (\mathcal{S}): hidden support,
* (\mathcal{I}): hidden active incidence family,
* (\mathcal{C}): hidden planted local constraint core,
* (\alpha): hidden local assignment or consistency labeling,
* (\pi): private embedding/permutation data,
* (\omega): hidden masking/slack state.

This is the concrete witness family later instantiated in `CoreC4`.

---

### 5. Intended security shape

The HICS family is intended to support:

* A1 through hidden sparse support + lossy projection,
* A2 through explicit transcript binding over public shell objects,
* A3 through a public encapsulation shell that lives in the same combinatorial language as public projections.

This is the core reason HICS was chosen.

---

### 6. Design philosophy

The public world should expose:

* coarse shape,
* admissibility structure,
* and transcript-facing statistics,

while the private world retains:

* exact support,
* exact incidences,
* exact planted core,
* exact local assignment,
* and exact embedding.

Many hidden coherent worlds should cast the same public shadow.

---

### 7. Immediate research risks

The HICS family is exposed to three obvious dangers:

1. the constraint language becoming too algebraic,
2. the public projection revealing too much hidden incidence structure,
3. the encapsulation shell becoming distinguishable from honest public combinatorial shells.

These are design risks, not theorem footnotes.

---

### 8. Role of CoreC3

`CoreC3` records the concrete family decision. It is the bridge between candidate evaluation (`CoreC2`) and concrete witness/projection language (`CoreC4`).