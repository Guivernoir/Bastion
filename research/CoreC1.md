# CoreC1.md

## Abstract Object Framework for the Combinatorial Module Base

### 1. Purpose

This document defines the **abstract object framework** for the proposed combinatorial module base intended to support a future unified post-quantum signcryption construction.

Its purpose is to specify, at a structural level:

* the hidden witness object,
* the public projection object,
* the public commitment object,
* the public encapsulation object,
* the semantic transcript object,
* and the public binding object.

This document is **not** an algorithm specification. It is the abstract habitat in which later concrete constructions must live. Its job is to constrain later design, not flatter it.

---

### 2. Design objective

The module base must support a future single-operation signcryption system with the following global properties:

1. one external signcrypt operation,
2. one master ephemeral entropy source,
3. internally domain-separated subroutines,
4. no forbidden state-sharing between authenticity and confidentiality,
5. transcript-complete binding,
6. a credible reduction path for confidentiality and authenticity.

The abstract object framework is therefore designed around **separation of roles under shared orchestration**: one root seed may exist, but the internal objects it drives must remain cryptographically distinct.

---

### 3. Global spaces and public context

Let (\lambda) be the security parameter.

We define the following abstract spaces:

* (\mathcal{X}_\lambda): witness space,
* (\mathcal{Y}_\lambda): public projection space,
* (\mathcal{W}_\lambda): commitment-object space,
* (\mathcal{E}_\lambda): encapsulation-object space,
* (\mathcal{M}_\lambda): semantic transcript-object space,
* (\mathcal{B}_\lambda): binding-object space,
* (\mathcal{AUX}_\lambda): public auxiliary context space.

The public auxiliary context `aux` includes:

* domain identifiers,
* version identifiers,
* role tags,
* public family parameters,
* admissibility rules,
* and any publicly fixed combinatorial universe definitions.

We write:
[
aux \leftarrow \mathsf{Setup}_\lambda.
]

---

### 4. Hidden witness object

A hidden witness is an object
[
x \in \mathcal{X}*\lambda,
]
generated according to a witness-generation algorithm
[
x \leftarrow \mathsf{GenWit}*\lambda(aux; \sigma_{wit}).
]

The witness is intended to encode the private structured combinatorial state of the sender or receiver, depending on role.

At the abstract level, the witness must support:

* efficient generation,
* efficient validity checking,
* efficient projection to a public object,
* and later, if needed, efficient derivation of commitment-facing structure.

The witness space is intentionally left abstract in `CoreC1`; concrete witness languages are introduced only in later core files.

---

### 5. Witness validity

Define a witness-validity predicate
[
\mathsf{ValidWit}*\lambda : \mathcal{X}*\lambda \times \mathcal{AUX}_\lambda \to {0,1}.
]

A witness (x) is **admissible** iff
[
\mathsf{ValidWit}_\lambda(x,aux)=1.
]

The validity predicate must be efficiently computable. Later assumptions and reductions depend on this. If the system cannot efficiently tell a valid witness from decorative nonsense, it is not a cryptographic primitive; it is a personality disorder in notation.

---

### 6. Public projection object

The public projection is defined by a deterministic efficiently computable map
[
\mathsf{Proj}*\lambda : \mathcal{X}*\lambda \times \mathcal{AUX}*\lambda \to \mathcal{Y}*\lambda.
]

For an admissible witness (x),
[
Y := \mathsf{Proj}_\lambda(x,aux)
]
is the public projection used by later protocol components.

The projection must satisfy:

1. efficient computability,
2. efficient public admissibility checking,
3. many-to-one geometry on admissible witnesses,
4. lossy exposure of hidden structure.

The projection is intended to reveal enough structure for:

* public keys,
* transcript binding,
* public verification-side admissibility,
* and authenticity/challenge formation,

while not exposing the full witness.

---

### 7. Commitment object

Define a commitment-forming interface
[
W \leftarrow \mathsf{Com}*\lambda(x; \sigma*{com}, aux),
\qquad W \in \mathcal{W}_\lambda.
]

The commitment object is the public object later used by the authenticity side to anchor its response relation.

At the abstract level, `Com` must satisfy:

* efficient computation from admissible witnesses,
* public representability,
* compatibility with transcript binding,
* no trivial inversion back to the witness,
* and compatibility with domain-separated coins.

The exact authenticity response equation is not specified in `CoreC1`.

---

### 8. Encapsulation object

Define a confidentiality-side interface
[
(encap, K) \leftarrow \mathsf{EncapCore}*\lambda(pk_R; \sigma*{enc}, aux),
\qquad encap \in \mathcal{E}_\lambda,\quad K \in {0,1}^{\kappa}.
]

Here `encap` is the public encapsulation object and `K` is the shared secret eventually used by the symmetric layer.

The encapsulation object must be:

* publicly transmissible,
* structurally admissible,
* compatible with a receiver-side recovery procedure,
* bindable into the signcryption transcript,
* and generated independently of live authenticity-internal witness state.

This last condition is not negotiable.

---

### 9. Semantic transcript object

Define the semantic transcript-object space (\mathcal{M}*\lambda).
An element
[
m \in \mathcal{M}*\lambda
]
is the protocol-level semantic packet object.

At the abstract level, a transcript contains:

* encapsulation object,
* ciphertext object,
* associated data,
* protocol context,
* sender and receiver public identifiers,
* and any additional metadata required for secure verification.

This transcript object is not just “what gets concatenated.” It is the semantic object that later gets bound and authenticated.

---

### 10. Binding object

Define the public binding map
[
B = \mathsf{Bind}*\lambda(Y,m,aux),
\qquad B \in \mathcal{B}*\lambda.
]

This is the public object that the authenticity layer will treat as the thing being authenticated.

The binding object must include:

* the exact public projection (Y),
* the exact semantic transcript object (m),
* explicit domain/version/role information from `aux`.

`Bind` must be deterministic, efficiently computable, and semantically complete.

---

### 11. Public keys

At the abstract level, we define sender and receiver public keys as role-tagged public objects:
[
pk_S = (Y_S,\theta_S,tag_S),
\qquad
pk_R = (Y_R,\theta_R,tag_R),
]
where:

* (Y_S, Y_R \in \mathcal{Y}_\lambda) are public projections,
* (\theta_S,\theta_R) are role-specific public auxiliary objects,
* `tag_S`, `tag_R` are domain/version/role tags.

The abstract framework does not require sender and receiver key structures to be identical.

---

### 12. Seed-derivation architecture

The final system is intended to use one master ephemeral seed
[
S_{root} \leftarrow {0,1}^{256},
]
with domain-separated derived sub-seeds
[
S_{wit},; S_{com},; S_{enc},; S_{sym}.
]

At the abstract level, `CoreC1` requires that:

* witness-generation coins,
* commitment-generation coins,
* encapsulation coins,
* and symmetric-layer coins

be derivable independently from (S_{root}) by domain separation.

This is a foundational invariant of the framework.

---

### 13. Design prohibitions

The abstract framework forbids the following:

1. deriving confidentiality-side public objects directly from live authenticity-internal witness state,
2. omitting security-relevant transcript fields from the binding object,
3. allowing multiple semantic meanings to share one transcript encoding,
4. allowing projection objects that are syntactically accepted but semantically undefined.

These are not implementation footnotes. They are theorem-preservation constraints.

---

### 14. Intended role of CoreC1

`CoreC1` serves as the common vocabulary and object grammar for all later documents.

It is intended to support:

* the root assumptions A1, A2, A3,
* later concrete combinatorial instantiations,
* later protocol algorithms,
* and later reduction theorems.

It does not itself claim security.

---

### 15. What CoreC1 does not fix

This document does **not** yet fix:

* the concrete combinatorial witness language,
* the concrete public projection loss function,
* the concrete encapsulation shell,
* the concrete commitment relation,
* or the final signcryption algorithm.

Those are delegated to later core files.