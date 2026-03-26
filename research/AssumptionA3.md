# Assumption Document A3

## Encapsulation Indistinguishability Hardness

### 1. Purpose

This assumption defines the **confidentiality root** of the combinatorial module base.

It formalizes the claim that a public encapsulation object hides a recoverable shared secret such that outsiders cannot distinguish real encapsulations from cover-distributed objects paired with unrelated random keys.

This is the assumption that will justify the main confidentiality game hop.

---

### 2. Abstract objects

Define the confidentiality-side algorithms:

* ((pk_R, sk_R) \leftarrow \mathsf{KeyGenEnc}_\lambda(aux)),
* ((encap, K) \leftarrow \mathsf{Encap}_\lambda(pk_R; \rho, aux)),
* (K \leftarrow \mathsf{Decap}_\lambda(sk_R, encap, aux)),

where:

* (encap \in \mathcal{E}_\lambda) is the public encapsulation object,
* (K \in {0,1}^\kappa) is the shared secret,
* (\rho) is encapsulation randomness.

Define also a public cover distribution:
[
encap^$ \leftarrow \mathcal{D}^{cover}_{\lambda,aux}(pk_R).
]

This cover distribution is the public object family into which real encapsulations must computationally blend.

---

### 3. Final assumption statement

## Assumption A3.1. Encapsulation Indistinguishability (CMB-IND)

For every probabilistic polynomial-time adversary (\mathcal{A}), there exists a negligible function (\mu(\lambda)) such that the following advantage is bounded by (\mu(\lambda)):

1. sample
   [
   aux \leftarrow \mathsf{Setup}*\lambda,\qquad
   (pk_R, sk_R) \leftarrow \mathsf{KeyGenEnc}*\lambda(aux),
   ]
2. give (pk_R, aux) to (\mathcal{A}),
3. sample (b \leftarrow {0,1}),
4. if (b=0), sample
   [
   (encap^*, K^*) \leftarrow \mathsf{Encap}_\lambda(pk_R; \rho, aux),
   ]
5. if (b=1), sample
   [
   encap^* \leftarrow \mathcal{D}^{cover}_{\lambda,aux}(pk_R),
   \qquad
   K^* \leftarrow {0,1}^{\kappa},
   ]
6. give ((encap^*, K^*)) to (\mathcal{A}),
7. let (b' \leftarrow \mathcal{A}(encap^*, K^*, pk_R, aux)).

Then
[
Adv^{\mathrm{CMB\text{-}IND}}_{\mathcal A}(\lambda)
===================================================

\left|\Pr[b'=b]-\frac12\right|
\le \mu(\lambda).
]

### Interpretation

The adversary cannot distinguish a real encapsulation-and-key pair from a cover-distributed encapsulation paired with a random key.

---

### 4. Stronger form

## Assumption A3.2. Chosen-Encapsulation Indistinguishability (CMB-IND-CCA)

In the same game, let the adversary additionally obtain oracle access to
[
\mathsf{Decap}_\lambda(sk_R,\cdot,aux)
]
on non-challenge encapsulation objects.

Then for every PPT adversary (\mathcal{A}),
[
Adv^{\mathrm{CMB\text{-}IND\text{-}CCA}}_{\mathcal A}(\lambda)
\le negl(\lambda).
]

### Interpretation

Even with decapsulation-oracle access on non-challenge encapsulations, the adversary cannot distinguish a real challenge shared secret from random.

This is the stronger target. Whether the final signcryption theorem relies on A3.2 directly or derives CCA security through authenticity composition is a design choice, but the stronger form should exist on paper.

---

### 5. Required structural properties

For A3 to be meaningful, the base must satisfy:

#### 5.1 Natural cover distribution

(\mathcal{D}^{cover}_{\lambda,aux}) should be a natural public distribution for encapsulation objects, not an artificial theorem prop.

#### 5.2 Correct decapsulation

For honest generation,
[
\Pr[\mathsf{Decap}_\lambda(sk_R,encap,aux)=K] \ge 1-negl(\lambda).
]

#### 5.3 Seed-injectable encapsulation randomness

The encapsulation algorithm must accept externally derived coins:
[
\rho = \mathsf{KDF}(S_{root}, \texttt{"ENC"}, aux),
]
or an equivalent domain-separated derivation.

#### 5.4 Explicit separation from signing randomness

Encapsulation randomness and signing randomness must be computationally independent conditioned on the master seed after domain separation. This is a design invariant, not a theorem garnish.

#### 5.5 Oracle interpretation note

The CCA oracle in A3.2 is a **base-module oracle** available to whoever holds (sk_R). In the final signcryption protocol, composition with the authenticity layer may restrict usable adversarial queries, but the base assumption itself is correctly stated with this stronger oracle.

---

### 6. Intended role

A3 is intended to support:

* the main confidentiality game hop,
* pseudorandom shared-secret derivation for the symmetric layer,
* transcript-safe composition where `encap` is public and authenticated but still confidentiality-relevant.

---

### 7. What A3 does not claim

A3 does **not** by itself imply:

* authenticity,
* transcript binding,
* full signcryption non-malleability,
* or complete outsider CCA security after composition.

---

### 8. Open review questions for A3

1. Is the cover distribution genuinely natural?
2. Can malformed encapsulations leak receiver information?
3. Does decapsulation failure amplify into a side-channel?
4. Does the cover distribution remain credible once encapsulations are bound into authenticated transcripts?