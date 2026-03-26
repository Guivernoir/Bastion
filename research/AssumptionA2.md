# Assumption Document A2

## Semantic Projection Binding Hardness

### 1. Purpose

This assumption defines the **public semantic binding** property of the module base. It formalizes the claim that once a projection is fixed, an adversary cannot produce two distinct semantic transcript objects that bind to the same authenticated public object.

A1 protects the hidden witness.
A2 protects the public meaning.

Those are different jobs. Treating them as one is how proofs develop mold.

---

### 2. Abstract objects

Let:

* (\mathcal{Y}_\lambda): public projection space,
* (\mathcal{M}_\lambda): transcript-object space,
* (\mathcal{S}_\lambda): semantic meaning space,
* (\mathcal{B}_\lambda): binding-object space.

Define:

* (\mathsf{ValidMsg}*\lambda : \mathcal{M}*\lambda \times \mathcal{AUX}_\lambda \to {0,1}),
* (\mathsf{Sem}*\lambda : \mathcal{M}*\lambda \times \mathcal{AUX}*\lambda \to \mathcal{S}*\lambda),
* (\mathsf{Bind}*\lambda : \mathcal{Y}*\lambda \times \mathcal{M}*\lambda \times \mathcal{AUX}*\lambda \to \mathcal{B}_\lambda).

The intended interpretation is:

* (Y) is the public projection,
* (m) is the structured transcript object,
* (\mathsf{Sem}(m,aux)) is its semantic meaning,
* (\mathsf{Bind}(Y,m,aux)) is the public object the authenticity layer treats as the thing being authenticated.

---

### 3. Why the assumption is worst-case over (Y)

In actual signcryption forgery games, the adversary may output a fresh public object whose projection component is **adversarially chosen**, not necessarily sampled from the honest witness distribution.

Therefore the binding assumption is stated over **all admissible public projections (Y)** in the projection space accepted by the verification layer, not only over honestly sampled (Y). This closes the main gap identified in review and prevents the theorem from silently excluding “bad” projections that an attacker might exploit.

---

### 4. Final assumption statement

## Assumption A2.1. Semantic Projection Binding Hardness (SPBH)

For every probabilistic polynomial-time adversary (\mathcal{A}), there exists a negligible function (\mu(\lambda)) such that
[
\Pr\Big[
\mathsf{ValidMsg}*\lambda(m_1,aux)=1
;\land;
\mathsf{ValidMsg}*\lambda(m_2,aux)=1
;\land;
\mathsf{Sem}*\lambda(m_1,aux)\neq \mathsf{Sem}*\lambda(m_2,aux)
;\land;
\mathsf{Bind}*\lambda(Y,m_1,aux)=\mathsf{Bind}*\lambda(Y,m_2,aux)
;:;
aux \leftarrow \mathsf{Setup}*\lambda,;
Y \leftarrow \mathcal{Y}*\lambda^{adm}(aux),;
(m_1,m_2)\leftarrow \mathcal{A}(Y,aux)
\Big]
\le \mu(\lambda),
]
where (\mathcal{Y}_\lambda^{adm}(aux)) denotes the set or distribution of **admissible public projections** accepted by the protocol syntax and verification layer.

### Interpretation

No efficient adversary, given any admissible projection (Y), can produce two valid transcript objects with different semantic meaning that bind to the same authenticated public object.

That is the right theorem target for signcryption. Byte-level uniqueness is for parsers. Semantic uniqueness is for security.

---

### 5. Weaker syntactic form

## Assumption A2.2. Syntactic Projection Binding Hardness

For every PPT adversary (\mathcal{A}),
[
\Pr\Big[
m_1 \neq m_2
;\land;
\mathsf{Bind}*\lambda(Y,m_1,aux)=\mathsf{Bind}*\lambda(Y,m_2,aux)
\Big]
\le negl(\lambda).
]

This weaker form may be useful internally, but it is not enough as the primary theorem target.

---

### 6. Required structural properties

For A2 to be meaningful, the base must satisfy:

#### 6.1 Canonical transcript encoding

Every valid semantic transcript must admit a unique canonical encoding.

#### 6.2 Full semantic coverage

Every security-relevant field must be inside the bound object:

* encapsulation,
* ciphertext,
* associated data,
* sender/receiver context,
* protocol version,
* domain tags,
* any auxiliary context used during verification.

#### 6.3 Domain-separated binding

If the same projection format may appear across roles or protocol classes, the binder must include explicit role and domain labels.

#### 6.4 Efficient deterministic binding

[
\mathsf{Bind}_\lambda(Y,m,aux)
]
must be deterministic and efficiently computable.

---

### 7. Relation to A1

A2 is kept as an independent assumption at this stage. However, later proofs must explicitly address the interaction between:

* alternate-witness attacks under A1.2, and
* semantic binding collisions under A2.1.

In particular, one must show either:

* that A2 does not silently reduce to A1 in the chosen instantiation, or
* that the composition theorem intentionally treats A2 as derived from A1 plus transcript-discipline lemmas.

This should not be left to implication by mood.

---

### 8. Intended role

A2 is intended to support:

* transcript non-malleability,
* CCA case splits where “same signature object, different semantic packet” must become a binding failure,
* transcript swapping and equivocation resistance,
* single-operation signcryption coherence.

---

### 9. What A2 does not claim

A2 does **not** by itself imply:

* witness hardness,
* signature unforgeability,
* confidentiality,
* KEM security,
* or random-oracle collision resistance.