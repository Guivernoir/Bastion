# CoreC2.md

## Candidate Concrete Families for the Combinatorial Module Base

### 1. Purpose

This document enumerates and evaluates the first concrete candidate families capable of instantiating the abstract object framework of `CoreC1`.

Its purpose is to identify which combinatorial families are serious enough to continue into concrete development, and which should be discarded before they consume time, notation, and dignity.

---

### 2. Evaluation criteria

Each candidate family is evaluated against the following criteria:

1. **A1 compatibility**
   Can it support hidden witness projection hardness with many-to-one projection geometry?

2. **A2 compatibility**
   Can it support canonical transcript binding and semantic non-equivocation?

3. **A3 compatibility**
   Can it support a plausible encapsulation object, a cover distribution, receiver-side recovery, and seed-derived independent coins?

4. **Quantum-resistance plausibility**
   Does it avoid immediate reduction to structures vulnerable to obvious quantum or algebraic attacks?

5. **Proof hygiene**
   Can one imagine proving something about it without inventing seven auxiliary assumptions just to keep the notation from crying?

---

### 3. Candidate family C2-A: Hidden Sparse Incidence Systems (HSIS)

#### Summary

The witness is a sparse hidden incidence structure over a public universe. The projection is a lossy shadow of support and incidence statistics.

#### Strengths

* strong fit for many-to-one projection geometry,
* naturally supports public shadows and hidden supports,
* good alignment with A1 and A2.

#### Weaknesses

* encapsulation story is not yet naturally elegant,
* may collapse into structured sparse-reconstruction problems that are easier than hoped.

#### Verdict

**Strong candidate**.

---

### 4. Candidate family C2-B: Hidden Compatible Path Systems (HCPS)

#### Summary

The witness is a hidden family of compatible paths through a large public graph or hypergraph.

#### Strengths

* intuitive structure,
* clean notion of hidden combinatorial coherence,
* naturally expressive for transcript binding.

#### Weaknesses

* graph/path families often admit decomposition attacks,
* high risk of quantum-walk or combinatorial-search improvements,
* encapsulation mechanism is less naturally grounded.

#### Verdict

**Promising but dangerous**.

---

### 5. Candidate family C2-C: Planted Constraint Core Systems (PCCS)

#### Summary

The witness is a planted satisfying core inside a larger public constraint shell.

#### Strengths

* very natural hidden witness / public shell split,
* strong fit for semantic binding,
* plausible receiver-side recovery story.

#### Weaknesses

* vulnerable if the constraint language becomes algebraic enough to invite elimination attacks,
* risk of SAT/SMT-style structural recovery.

#### Verdict

**Very strong candidate**.

---

### 6. Candidate family C2-D: Hidden Sparse Matching Systems (HSMS)

#### Summary

The witness is a hidden matching or family of sparse compatible matchings in a public multipartite structure.

#### Strengths

* very clean witness validity,
* easy to state and verify,
* naturally combinatorial.

#### Weaknesses

* weaker path to a rich encapsulation layer,
* closer to classical combinatorial optimization templates than desired.

#### Verdict

**Backup candidate only**.

---

### 7. Candidate family C2-E: Hybrid Incidence-Constraint Systems (HICS)

#### Summary

The witness is both:

* a hidden sparse incidence structure, and
* a hidden planted local constraint core on top of it.

#### Strengths

* strongest fit to A1,
* strongest fit to A2,
* best chance of supporting a native encapsulation shell for A3,
* richest design space for single-operation signcryption.

#### Weaknesses

* the most complex,
* most exposed to accidental structural leakage,
* easiest to make unsafely elegant.

#### Verdict

**Primary research candidate**.

---

### 8. Candidate ranking

#### Tier 1

* `C2-E` Hybrid Incidence-Constraint Systems
* `C2-C` Planted Constraint Core Systems
* `C2-A` Hidden Sparse Incidence Systems

#### Tier 2

* `C2-B` Hidden Compatible Path Systems

#### Tier 3

* `C2-D` Hidden Sparse Matching Systems

---

### 9. Selection decision

For the first concrete development branch, the chosen family is:

[
\boxed{\text{C2-E: Hybrid Incidence-Constraint Systems (HICS)}}
]

This choice is made because HICS offers the strongest unified fit across A1, A2, and A3, even though it is the most dangerous to instantiate carelessly.

The safer fallback family is `C2-C`.

---

### 10. Role of CoreC2

`CoreC2` justifies the transition from the abstract object framework of `CoreC1` to the concrete family selected in `CoreC3`.

It does not itself define the final object language.