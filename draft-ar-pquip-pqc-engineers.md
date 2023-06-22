---
title: "Post-Quantum Cryptography for Engineers"
abbrev: "PQC for Engineers"
category: info

docname: draft-ar-pquip-pqc-engineers
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "PQUIP"
keyword:
 - PQC
 

venue:
  group: "pquip"
  type: "Working Group"
  mail: "pquip@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/pquip/"
  

stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Aritra Banerjee
    organization: Nokia
    city: Munich
    country: Germany
    email: "aritra.banerjee@nokia.com"
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
 -
    fullname: Dimitrios Schoinianakis
    organization: Nokia 
    city: Athens
    country: Greece
    email: "dimitrios.schoinianakis@nokia-bell-labs.com"
 -
    fullname: Timothy Hollebeek
    organization: DigiCert
    city: Pittsburgh
    country: USA
    email: "tim.hollebeek@digicert.com"


normative:

informative:

  Grover-search:
     title: "C. Zalka, “Grover’s quantum searching algorithm is optimal,” Physical Review A, vol. 60, pp. 2746-2751, 1999."
     target: 
     date: false
  Threat-Report:
     title: "Quantum Threat Timeline Report 2020"
     target: https://globalriskinstitute.org/publications/quantum-threat-timeline-report-2020/
     date: false
  IBM:
     title: "IBM Unveils 400 Qubit-Plus Quantum Processor and Next-Generation IBM Quantum System Two"
     target: https://newsroom.ibm.com/2022-11-09-IBM-Unveils-400-Qubit-Plus-Quantum-Processor-and-Next-Generation-IBM-Quantum-System-Two
     date: false     
  Google:
     title: "Quantum Supremacy Using a Programmable Superconducting Processor"
     target: https://ai.googleblog.com/2019/10/quantum-supremacy-using-programmable.html
     date: false  
  QC-DNS:
     title: "Quantum Computing and the DNS"
     target: https://www.icann.org/octo-031-en.pdf
     date: false 
  NIST:
     title: "Post-Quantum Cryptography Standardization"
     target: https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization
     date: false
  Nokia:
     title: "Interference Measurements of Non-Abelian e/4 & Abelian e/2 Quasiparticle Braiding"
     target: https://journals.aps.org/prx/pdf/10.1103/PhysRevX.13.011028
     date: false
  Cloudflare:
     title: "NIST’s pleasant post-quantum surprise"
     target: https://blog.cloudflare.com/nist-post-quantum-surprise/
     date: false  
  IBMRoadmap:
     title: "The IBM Quantum Development Roadmap"
     target: https://www.ibm.com/quantum/roadmap
     date: false
  Falcon:
     title: "Fast Fourier lattice-based compact signatures over NTRU"
     target: https://falcon-sign.info/
     date: false
  Dilithium:
     title: "Cryptographic Suite for Algebraic Lattices (CRYSTALS) - Dilithium"
     target: https://pq-crystals.org/dilithium/index.shtml
     date: false
  SPHINCS:
     title: "SPHINCS+"
     target: https://sphincs.org/index.html
     date: false
  RSA:
     title: "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems+"
     target: https://dl.acm.org/doi/pdf/10.1145/359340.359342 
     date: false
  CS01:
     title: "Design and Analysis of Practical Public-Key Encryption Schemes Secure against Adaptive Chosen Ciphertext Attack"
     target: https://eprint.iacr.org/2001/108 
     date: false
  BHK09:
     title: "Subtleties in the Definition of IND-CCA: When and How Should Challenge-Decryption be Disallowed?"
     target: https://eprint.iacr.org/2009/418 
     date: false
  GMR88:
     title: "A digital signature scheme secure against adaptive chosen-message attacks."
     target: https://people.csail.mit.edu/silvio/Selected%20Scientific%20Papers/Digital%20Signatures/A_Digital_Signature_Scheme_Secure_Against_Adaptive_Chosen-Message_Attack.pdf 
     date: false
  PQCAPI:
     title: "PQC - API notes"
     target: https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/example-files/api-notes.pdf
     date: false
     
--- abstract

The presence of a Cryptographically Relevant Quantum Computer (CRQC) would render state-of-the-art, public-key cryptography deployed today obsolete, since all the assumptions about the intractability of the mathematical problems that offer confident levels of security today no longer apply in the presence of a CRQC.  This means there is a requirement to update protocols and infrastructure to use post-quantum algorithms, which are public-key algorithms designed to be secure against CRQCs as well as classical computers.  These algorithms are just like previous public key algorithms, however the intractable mathematical problems have been carefully chosen, so they are hard for CRQCs as well as classical computers. This document explains why engineers need to be aware of and understand post-quantum cryptography. It emphasizes the potential impact of CRQCs on current cryptographic systems and the need to transition to post-quantum algorithms to ensure long-term security.  The most important thing to understand is that this transition is not like previous transitions from DES to AES or from SHA-1 to SHA2, as the algorithm properties are significantly different from classical algorithms, and a drop-in replacement is not possible. 

--- middle

# Introduction

Quantum computing is no longer perceived as a conjecture of computational sciences and theoretical physics. Considerable research efforts and enormous corporate and government funding for the development of practical quantum computing systems are being invested currently. For instance, Google’s announcement on achieving quantum supremacy {{Google}}, IBM’s latest 433-qubit processor Osprey {{IBM}} or even Nokia Bell Labs' work on topological qubits {{Nokia}} signify, among other outcomes, the accelerating efforts towards large-scale quantum computers. At the time of writing the document, Cryptographically Relevant Quantum Computers (CRQCs) that can break widely used public-key cryptographic algorithms are not yet available. However, it is worth noting that there is ongoing research and development in the field of quantum computing, with the goal of building more powerful and scalable quantum computers. As quantum technology advances, there is the potential for future quantum computers to have a significant impact on current cryptographic systems.  Forecasting the future is difficult, but the general consensus is that such computers might arrive some time in the 2030s, or might not arrive until 2050 or later.

Extensive research has produced several post-quantum cryptographic algorithms that offer the potential to ensure cryptography's survival in the quantum computing era. However, transitioning to a post-quantum infrastructure is not a straightforward task, and there are numerous challenges to overcome. It requires a combination of engineering efforts, proactive assessment and evaluation of available technologies, and a careful approach to product development. This document aims to provide general guidance to engineers who utilize public-key cryptography in their software. It covers topics such as selecting appropriate post-quantum cryptographic (PQC) algorithms, understanding the differences between PQC Key Encapsulation Mechanisms (KEMs) and traditional Diffie-Hellman style key exchange, and provides insights into expected key sizes and processing time differences between PQC algorithms and traditional ones. Additionally, it discusses the potential threat to symmetric cryptography from Cryptographically Relevant Quantum Computers (CRQCs).  It is important to remember that asymmetric algorithms are largely used for secure communications between organizations that may not have previously interacted, so a significant amount of coordination between organizations, and within and between ecosystems needs to be taken into account.  Such transitions are some of the most complicated in the tech industry.
 
It is crucial for the reader to understand that when the word "PQC" is mentioned in the document, it means Asymmetric Cryptography (or Public key Cryptography) and not any algorithms from the Symmetric side based on stream, block ciphers, etc. It does not cover such topics as when traditional algorithms might become vulnerable (for that, see documents such as [QC-DNS] and others).  It also does not cover unrelated technologies like Quantum Key Distribution or Quantum Key Generation, which use quantum hardware to exploit quantum effects to protect communications and generate keys, respectively.  Post-quantum cryptography is based on standard math and software and can be run on any general purpose computer.

Please note: This document does not go into the deep mathematics of the PQC algorithms, but rather provides an overview to engineers on the current threat landscape and the relevant algorithms designed to help prevent those threats. 

# Conventions and Definitions

{::boilerplate bcp14-tagged}

# Contributing to This Document

The guide was inspired by a thread in September 2022 on the <mailto:pqc@ietf.org> mailing list.
The document is being collaborated on through a [GitHub repository](https://github.com/tireddy2/pqc-for-engineers).

The editors actively encourage contributions to this document. Please consider writing a section on a topic that you think is missing. Short of that, writing a paragraph or two on an issue you found when writing code that uses PQC would make this document more useful to other coders. Opening issues that suggest new material is fine too, but relying on others to write the first draft of such material is much less likely to happen than if you take a stab at it yourself.

# Traditional Cryptographic Primitives that Could Be Replaced by PQC

Any asymmetric cryptographic algorithm based on integer factorization, finite field discrete logarithms or elliptic curve discrete logarithms will be vulnerable to attacks using Shor's Algorithm on a sufficiently large general-purpose quantum computer, known as a CRQC. This document focuses on the principal functions of asymmetric cryptography:

* Key Agreement:  Key Agreement schemes are used to establish a shared cryptographic key for secure communication. They are one of the mechanisms that can replaced by PQC, as this is based on public key cryptography and is therefore vulnerable to the Shor's algorithm. An CRQC can find the prime factors of the large public key, which can used to derive the private key.

* Digital Signatures: Digital Signature schemes are used to authenticate the identity of a sender, detect unauthorized modifications to data and underpin trust in a system. Signatures, similar to KEMs also depend on public-private key pair and hence a break in public key cryptography will also affect traditional digital signatures, hence the importance of developing post quantum digital signatures.  

# Invariants of Post-Quantum Cryptography

 In the context of PQC, symmetric-key cryptographic algorithms are generally not directly impacted by quantum computing advancements. Symmetric-key cryptography, such as block ciphers (e.g., AES) and hash functions (e.g., HMAC-SHA2), rely on secret keys shared between the sender and receiver. HMAC is a specific construction that utilizes a cryptographic hash function (such as SHA-2) and a secret key shared between the sender and receiver to produce a message authentication code. CRQCs, in theory, do not offer substantial advantages in breaking symmetric-key algorithms compared to classical computers (see {{symmetric}} for more details).

# NIST PQC Algorithms

In 2016, the National Institute of Standards and Technology (NIST) started a process to solicit, evaluate, and standardize one or more quantum-resistant public-key cryptographic algorithms, as seen [here](https://csrc.nist.gov/projects/post-quantum-cryptography). The first set of algorithms for standardization (https://csrc.nist.gov/publications/detail/nistir/8413/final) were selected in July 2022.

NIST announced as well that they will be [opening a fourth round](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/guidelines-for-submitting-tweaks-fourth-round.pdf) to standardize an alternative KEM, and a [call](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/call-for-proposals-dig-sig-sept-2022.pdf) for new candidates for a post-quantum signature algorithm.

These algorithms are not a drop-in replacement for classical asymmetric cryptographic algorithms.  RSA [RSA] and ECC {{?RFC6090}} can be used for both key encapsulation and signatures, while for post-quantum algorithms, a different algorithm is needed for each.  When upgrading protocols, it is important to replace the existing use of classical algorithms with either a PQC key encapsulation method or a PQC signature method, depending on how RSA and/or ECC was previously being used.

## NIST candidates selected for standardization

### PQC Key Encapsulation Mechanisms (KEMs)

* [CRYSTALS-Kyber](https://pq-crystals.org/kyber/): Kyber is a module learning with errors (MLWE)-based key encapsulation mechanism.

### PQC Signatures

* [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
* [Falcon](https://falcon-sign.info/)
* [SPHINCS+](https://sphincs.org/)

## Candidates advancing to the fourth-round for standardization at NIST

The fourth-round of the NIST process only concerns with KEMs.
The candidates still advancing for standardization are:

* [Classic McEliece](https://classic.mceliece.org/)
* [BIKE](https://bikesuite.org/)
* [HQC](http://pqc-hqc.org/)
* [SIKE](https://sike.org/) (Broken): Supersingular Isogeny Key Encapsulation (SIKE) is a specific realization of the SIDH (Supersingular Isogeny Diffie-Hellman) protocol. Recently, a [mathematical attack](https://eprint.iacr.org/2022/975.pdf) based on the "glue-and-split" theorem from 1997 from Ernst Kani was found against the underlying chosen starting curve and torsion information. In practical terms, this attack allows for the efficient recovery of the private key. NIST announced that SIKE was no longer under consideration, but the authors of SIKE had asked for it to remain in the list so that people are aware that it is broken.

# Threat of CRQCs on Cryptography

Post-quantum cryptography or quantum-safe cryptography refers to cryptographic algorithms that are secure against cryptographic attacks from both CRQCs and classic computers.

When considering the security risks associated with the ability of a quantum computer to attack traditional cryptography, it is important to distinguish between the impact on symmetric algorithms and public-key ones. Dr. Peter Shor and Dr. Lov Grover developed two algorithms that changed the way the world thinks of security under the presence of a CRQC. 

## Symmetric cryptography {#symmetric}

Grover's algorithm is a quantum search algorithm that provides a theoretical quadratic speedup for searching an unstructured database compared to classical algorithms. Grover’s algorithm theoretically requires doubling the key sizes of the algorithms that one deploys today to achieve quantum resistance. This is because Grover’s algorithm reduces the amount of operations to break 128-bit symmetric cryptography to 2^{64} quantum operations, which might sound computationally feasible. However, 2^{64} operations performed in parallel are feasible for modern classical computers, but 2^{64} quantum operations performed serially in a quantum computer are not. Grover's algorithm is highly non-parallelizable and even if one deploys 2^c computational units in parallel to brute-force a key using Grover's algorithm, it will complete in time proportional to 2^{(128−c)/2}, or, put simply, using 256 quantum computers will only reduce runtime by 1/16, 1024 quantum computers will only reduce runtime by 1/32 and so forth ​(see {{NIST}} and {{Cloudflare}}​). 

For unstructured data such as symmetric encrypted data or cryptographic hashes, although CRQCs can search for specific solutions across all possible input combinations (e.g., Grover's Algorithm), no CRQCs is known  to break the security properties of these classes of algorithms.

How can someone be sure then that an improved algorithm won’t outperform Grover's algorithm at some point in time? Christof Zalka has shown that Grover's algorithm (and in particular its non-parallel nature) achieves the best possible complexity for unstructured search {{Grover-search}}.

Finally, in their evaluation criteria for PQC, NIST is considering a security level equivalent to that of AES-128, meaning that NIST has confidence in standardizing parameters for PQC that offer similar levels of security as AES-128 does {{NIST}}​. As a result, 128-bit algorithms should be considered quantum-safe for many years to come. 


## Asymmetric cryptography

“Shor’s algorithm” on the other side, efficiently solves the integer factorization problem (and the related discrete logarithm problem), which offer the foundations of the public-key cryptography that the world uses today. This implies that, if a CRQC is developed, today’s public-key cryptography algorithms (e.g., RSA, Diffie-Hellman and Elliptic Curve Cryptography - ECC) and the accompanying digital signatures schemes and protocols would need to be replaced by algorithms and protocols that can offer cryptanalytic resistance against CRQCs. Note that Shor’s algorithm doesn’t run on any classic computer, it needs a CRQC. 

For structured data such as public-key and signatures, instead, CRQCs can fully solve the underlying hard problems used in classic cryptography (see Shor's Algorithm). Because an increase of the size of the key-pair would not provide a secure solution in this case, a complete replacement of the algorithm is needed. Therefore, post-quantum public-key cryptography must rely on problems that are different from the ones used in classic public-key cryptography (i.e., the integer factorization problem, the finite-field discrete logarithm problem, and the elliptic-curve discrete logarithm problem). 


# Timeline for transition

A malicious actor with adequate resources can launch an attack to store sensitive encrypted data today that can be decrypted once a CRQC is available. This implies that, every day, sensitive encrypted data is susceptible to the attack by not implementing quantum-safe strategies, as it corresponds to data being deciphered in the future.  

~~~~~

+------------------------+----------------------------+
|                        |                            |
|         y              |           x                |
+------------------------+----------+-----------------+
|                                   |
|               z                   |
+-----------------------------------+

~~~~~
{: #Mosca title="Mosca model"}

These challenges are illustrated nicely by the so called Mosca model discussed in ​{{Threat-Report}}. In the {{Mosca}}, "x" denotes the time that our systems and data need to remain secure, "y" the number of years to migrate to a PQC infrastructure and "z" the time until a CRQC that can break current cryptography is available. The model assumes that encrypted data can be intercepted and stored before the migration is completed in "y" years. This data remains vulnerable for the complete "x" years of their lifetime, thus the sum "x+y" gives us an estimate of the full timeframe that data remain insecure​. The model essentially asks how are we preparing our IT systems during those "y" years (or in other words, how can one minimize those "y" years) to minimize the transition phase to a PQC infrastructure and hence minimize the risks of data being exposed in the future. 

Finally, other factors that could accelerate the introduction of a CRQC should not be under-estimated, like for example faster-than-expected advances in quantum computing and more efficient versions of Shor’s algorithm requiring less qubits. As an example, IBM, one of the leading actors in the development of a large-scale quantum computer, has recently published a roadmap committing to new quantum processors supporting more than 1000 qubits by 2025 and networked systems with 10k-100k qubits beyond 2026 {{IBMRoadmap}}. Innovation often comes in waves, so it is to the industry’s benefit to remain vigilant and prepare as early as possible. 

# Post-quantum cryptography categories 

The current set of problems used in post-quantum cryptography can be currently grouped into three different categories: lattice-based, hash-based and code-based.

## Lattice-Based Public-Key Cryptography

Lattice-based public-key cryptography leverages the simple construction of lattices (i.e., a regular collection of points in a Euclidean space that are regularly spaced) to build problems that are hard to solve such as the Shortest Vector or Closes Vector Problem, Learning with Errors, and Learning with Rounding. All these problems have good proof for worst-to-average case reduction, thus equating the hardness of the average case to the worst-case.

The possibility to implement public-key schemes on lattices is tied to the characteristics of the basis used for the lattice. In particular, solving any of the mentioned problems can be easy when using reduced or "good" basis (i.e., as short as possible and as orthogonal as possible), while it becomes computationally infeasible when using "bad" basis (i.e., long vectors not orthogonal). Although the problem might seem trivial, it is computationally hard when considering many dimensions. Therefore, a typical approach is to use "bad" basis for public keys and "good" basis for private keys. The public keys ("bad" basis) let you easily verify signatures by checking, for example, that a vector is the closest or smallest, but do not let you solve the problem (i.e., finding the vector). Conversely, private keys (i.e., the "good" basis) can be used for generating the signatures (e.g., finding the specific vector). Signing is equivalent to solving the lattice problem.

Lattice-based schemes usually have good performances and average size public keys and signatures, making them good candidates for general-purpose use such as replacing the use of RSA in PKIX certificates.

Examples of such class of algorithms include Kyber, Falcon and Dilithium.

## Hash-Based Public-Key Cryptography {#hash-based}

Hash based PKC has been around since the 70s, developed by Lamport and Merkle which creates a digital signature algorithm and its security is mathematically based on the security of the selected cryptographic hash function. Many variants of hash based signatures have been developed since the 70s including the recent XMSS, LMS or BPQS schemes. Unlike digital signature techniques, most hash-based signature schemes are stateful, which means that signing necessitates the update of the secret key.

SPHINCS on the other hand leverages the HORS (Hash to Obtain Random Subset) technique and remains the only hash based signature scheme that is stateless.

SPHINCS+ is an advancement on SPHINCS which reduces the signature sizes in SPHINCS and makes it more compact. SPHINCS+ was recently standardized by NIST.

## Code-Based Public-Key Cryptography

This area of cryptography stemmed in the 1970s and 80s based on the seminal work of McEliece and Niederreiter which focuses on the study of cryptosystems based on error-correcting codes. Some popular error correcting codes include the Goppa codes (used in McEliece cryptosystems), encoding and decoding syndrome codes used in Hamming Quasi-Cyclic (HQC) or Quasi-cyclic Moderate density parity check (QC-MDPC) codes.

Examples include all the NIST Round 4 (unbroken) finalists: Classic McEliece, HQC, BIKE.


# KEMs

## What is a KEM

Key Encapsulation Mechanism (KEM) is a cryptographic technique used for securely exchanging symmetric keys between two parties over an insecure channel. It is commonly used in hybrid encryption schemes, where a combination of asymmetric (public-key) and symmetric encryption is employed. The KEM encapsulation results in a fixed-length symmetric key that can be used in one of two ways: (1) Derive a Data Encryption Key (DEK) to encrypt the data (2) Derive a Key Encryption Key (KEK) used to wrap the DEK. 

It is, however, essential to note that PQ KEMs are interactive in nature because the sender's actions are dependent on the receiver's public key and unlike Diffie-Hellman (DH) Key exchange (KEX) which provides non-interactive key exchange (NIKE) property.

KEM relies on the following primitives [PQCAPI]:

* def kemKeyGen() -> (pk, sk)
* def kemEncaps(pk) -> (ct, ss)
* def kemDecaps(ct, sk) -> ss

where pk is public key, sk is secret key, ct is the ciphertext representing an encapsulated key, and ss is shared secret.  The following figure illustrates a sample flow of KEM

~~~~~ aasvg

                      +---------+ +---------+
                      | Client  | | Server  |
                      +---------+ +---------+
  -----------------------\ |           |
  | sk, pk = kemKeyGen() |-|           |
  |----------------------| |           |
                           |           |
                           | pk        |
                           |---------->|
                           |           | -------------------------\
                           |           |-| ss, ct = kemEncaps(pk) |
                           |           | |------------------------|
                           |           |
                           |        ct |
                           |<----------|
-------------------------\ |           |
| ss = kemDecaps(ct, sk) |-|           |
|------------------------| |           |
                           |           |


~~~~~

## HPKE

HPKE (Hybrid public key encryption) {{?RFC9180}} deals with a variant of KEM which is essentially a PKE of arbitrary sized plaintexts for a recipient public key. It works with a combination of KEMs, KDFs and AEAD schemes (Authenticated Encryption with Additional Data). HPKE includes three authenticated variants, including one that authenticates possession of a pre-shared key and two optional ones that authenticate possession of a key encapsulation mechanism (KEM) private key. Kyber, which is a KEM does not support the static-ephemeral key exchange that allows HPKE based on DH based KEMs its (optional) authenticated modes as discussed in Section 1.2 of {{?I-D.westerbaan-cfrg-hpke-xyber768d00-02}}. 

## Security property

* IND-CCA2 : IND-CCA2 (INDistinguishability under Chosen-Ciphertext Attack, version 2) is an advanced security notion for encryption schemes. It ensures the confidentiality of the plaintext, resistance against chosen-ciphertext attacks, and prevents the adversary from forging new ciphertexts. An appropriate definition of IND-CCA2 security for KEMs can be found in [CS01] and [BHK09]. Kyber, Classic McEliece and Saber provide IND-CCA2 security. 

Understanding IND-CCA2 security is essential for individual involved in designing or implementing cryptographic systems to evaluate the strength of the algorithm, assess its suitability for specific use cases, and ensure that data confidentiality and security requirements are met.

# PQC Signatures

## What is a Post-quantum Signature

Any digital signature scheme that provides a construction defining security under post quantum setting falls under this category of PQ signatures. 

## Security property

* EUF-CMA : EUF-CMA (Existential Unforgeability under Chosen Message Attack) [GMR88] is a security notion for digital signature schemes. It guarantees that an adversary, even with access to a signing oracle, cannot forge a valid signature for an unknown message. EUF-CMA provides strong protection against forgery attacks, ensuring the integrity and authenticity of digital signatures by preventing unauthorized modifications or fraudulent signatures. Dilithium, Falcon and Sphincs+ provide EUF-CMA security. 

Understanding EUF-CMA security is essential for individual involved in designing or implementing cryptographic systems to ensure the security, reliability, and trustworthiness of digital signature schemes. It allows for informed decision-making, vulnerability analysis, compliance with standards, and designing systems that provide strong protection against forgery attacks.

## Details of FALCON, Dilithium, and SPHINCS+

Dilithium [Dilithium] is a digital signature algorithm (part of the CRYSTALS suite) based on the hardness lattice problems over module lattices (i.e., the Module Learning with Errors problem(MLWE)). The design of the algorithm is based on Fiat Shamir with Abort method that leverages rejection sampling to render lattice based FS schemes compact and secure. Additionally, Dilithium offers both deterministic and randomized signing. Security properties of Dilithium are discussed in Section 9 of {{?I-D.ietf-lamps-dilithium-certificates}}. 

Falcon [Falcon] is based on the GPV hash-and-sign lattice-based signature framework introduced by Gentry, Peikert and Vaikuntanathan, which is a framework that requires a class of lattices and a trapdoor sampler technique. 

The main design principle of Falcon is compactness, i.e. it was designed in a way that achieves minimal total memory bandwidth requirement (the sum of the signature size plus the public key size). This is possible due to the compactness of NTRU lattices.  Falcon also offers very efficient signing and verification procedures. The main potential downsides of Falcon refer to the non-triviality of its algorithms and the need for floating point arithmetic support.

Access to a robust floating-point stack in Falcon is essential for accurate, efficient, and secure execution of the mathematical computations involved in the scheme. It helps maintain precision, supports error correction techniques, and contributes to the overall reliability and performance of Falcon's cryptographic operations.

The performance characteristics of Dilithium and Falcon may differ based on the specific implementation and hardware platform. Generally, Dilithium is known for its relatively fast signature generation, while Falcon can provide more efficient signature verification. The choice may depend on whether the application requires more frequent signature generation or signature verification. For further clarity, please refer to the tables in sections {{RecSecurity}} and {{Comparisons}}.

Sphincs+ [SPHINCS] utilizes the concept of stateless hash-based signatures, where each signature is unique and unrelated to any previous signature (as discussed in {{hash-based}}). This property eliminates the need for maintaining state information during the signing process. Other hash-based signature algorithms are stateful, including HSS/LMS {{!RFC8554}} and XMSS {{!RFC8391}}. SPHINCS+ was designed to sign up to 2^64 messages and it offers three security levels. The parameters for each of the security levels were chosen to provide 128 bits of security, 192 bits of security, and 256 bits of security.  Sphincs+ offers smaller key sizes, larger signature sizes, slower signature generation, and slower verification when compared to Dilithium and Falcon. SPHINCS+ does not introduce a new intractability assumption. It builds upon established foundations in cryptography, making it a reliable and robust digital signature scheme for a post-quantum world. The advantages and disadvantages of SPHINCS+ over other signature algorithms is disussed in Section 3.1 of {{?I-D.draft-ietf-cose-sphincs-plus}}.

## Hash-then-Sign Versus Sign-then-Hash

Within the hash-then-sign paradigm, the message is hashed before signing it.  Hashing the message before signing it provides an additional layer of security by ensuring that only a fixed-size digest of the message is signed, rather than the entire message itself. By pre-hashing, the onus of resistance to existential forgeries becomes heavily reliant on the collision-resistance of the hash function in use.  As well as this security goal, the hash-then-sign paradigm also has the ability to improve performance by reducing the size of signed messages.  As a corollary, hashing remains mandatory even for short messages and assigns a further computational requirement onto the verifier.  This makes the performance of hash-then-sign schemes more consistent, but not necessarily more efficient. Using a hash function to produce a fixed-size digest of a message ensures that the signature is compatible with a wide range of systems and protocols, regardless of the specific message size or format.  Hash-then-Sign also greatly reduces the amount of data that needs to be processed by a hardware security module, which sometimes have somewhat limited data processing capabilities. 

Protocols like TLS 1.3 and DNSSEC use the Hash-then-Sign paradigm. TLS 1.3 {{?RFC8446}} uses it in the Certificate Verify to proof that the endpoint possesses the private key corresponding to its certificate, while DNSSEC {{?RFC4033}} uses it to provide origin authentication and integrity assurance services for DNS data.

In the case of Dilithium, it internally incorporates the necessary hash operations as part of its signing algorithm. Dilithium directly takes the original message, applies a hash function internally, and then uses the resulting hash value for the signature generation process. Therefore, the hash-then-sign paradigm is not needed for Dilithium, as it already incorporates hashing within its signing mechanism. In case of SPHINCS+, it internally performs randomized message compression using an keyed hash function that can process arbitrary length messages. Therefore, the hash-then-sign paradigm is also not needed for SPHINCS+.

# Recommendations for Security / Performance Tradeoffs {#RecSecurity}

The table below denotes the 5 security levels provided by NIST required for PQC algorithms. Users can leverage the required algorithm based on the security level based on their use case. The security is defined as a function of resources required to break AES and SHA3 algorithms, i.e., optimal key recovery for AES and optimal collision attacks for SHA3.

| Security Level |            AES/SHA3 hardness       |                   PQC Algorithm                            |
| -------------- | ---------------------------------- | ---------------------------------------------------------- |
|       1        | Find optimal key in AES-128        |          Kyber512, Falcon512, Sphincs+SHA256 128f/s        |
|       2        | Find optimal collision in SHA3-256 |                       Dilithium2                           |
|       3        | Find optimal key in AES-192        |         Kyber768, Dilithium3, Sphincs+SHA256 192f/s        |
|       4        | Find optimal collision in SHA3-384 |                   No algorithm tested at this level        |
|       5        | Find optimal key in AES-256        |   Kyber1024, Falcon1024, Dilithium5, Sphincs+SHA256 256f/s |

Please note the Sphincs+SHA256 x"f/s" in the above table denotes whether its the Sphincs+ fast (f) version or small (s) version for "x" bit AES security level. Refer to {{?I-D.ietf-lamps-cms-sphincs-plus-02}} for further details on Sphincs+ algorithms.

The following table discusses the impact of performance on different security levels in terms of private key sizes, public key sizes and ciphertext/signature sizes.

| Security Level |            Algorithm       | Public key size (in bytes)  | Private key size (in bytes)  | Ciphertext/Signature size (in bytes) |
| -------------- | -------------------------- | --------------------------- | ---------------------------  | ------------------------------------ |
|       1        |            Kyber512        |       800                   |          1632                |             768                      |
|       2        |           Dilithium2       |       1312                  |          2528                |            2420                      |
|       3        |            Kyber768        |       1184                  |          2400                |            1088                      |
|       5        |           Falcon1024       |       1793                  |          2305                |            1330                      |
|       5        |            Kyber1024       |       1568                  |          3168                |            1588                      |

# Comparing PQC KEMs/Signatures vs Traditional KEMs (KEXs)/Signatures {#Comparisons}

In this section, we provide two tables for comparison of different KEMs and Signatures respectively, in the traditional and Post scenarios. These tables will focus on the secret key sizes, public key sizes, and ciphertext/signature sizes for the PQC algorithms and their traditional counterparts of similar security levels.

The first table compares traditional vs. PQC KEMs in terms of security, public, private key sizes, and ciphertext sizes.

| PQ Security Level |            Algorithm       | Public key size (in bytes)  | Private key size (in bytes)  |         Ciphertext size (in bytes)   |
| ----------------- | -------------------------- | --------------------------- | ---------------------------  | ------------------------------------ |
|      Traditional  |        P256_HKDF_SHA256    |       65                    |          32                  |            65                        |
|      Traditional  |        P521_HKDF_SHA512    |       133                   |          66                  |            133                       |
|      Traditional  |       X25519_HKDF_SHA256   |       32                    |          32                  |            32                        |
|          1        |            Kyber512        |       800                   |          1632                |            768                       |
|          3        |            Kyber768        |       1184                  |          2400                |            1088                      |
|          5        |            Kyber1024       |       1568                  |          3168                |            1588                      |

The next table compares traditional vs. PQC Signature schemes in terms of security, public, private key sizes, and signature sizes.

| PQ Security Level |            Algorithm       | Public key size (in bytes)  | Private key size (in bytes)  |         Signature size (in bytes)    |
| ----------------- | -------------------------- | --------------------------- | ---------------------------  | ------------------------------------ |
|      Traditional  |              RSA2048       |       256                   |          256                 |            256                       |
|      Traditional  |               P256         |       64                    |          32                  |            64                        |
|          2        |            Dilithium2      |       1312                  |          2528                |            768                       |
|          3        |            Dilithium3      |       1952                  |          4000                |            3293                      |
|          5        |            Falcon1024      |       1793                  |          2305                |            1330                      |

As one can clearly observe from the above tables, leveraging a PQC KEM/Signature significantly increases the key sizes and the ciphertext/signature sizes as well as compared to traditional KEM(KEX)/Signatures. But the PQC algorithms do provide the additional security level in case there is an attack from a CRQC, whereas schemes based on prime factorization or discrete logarithm problems (finite field or elliptic curves) would provide no level of security at all against such attacks.

# Post-Quantum and Traditional Hybrid Schemes

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, and hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there may be a desire or a requirement for protocols that use both algorithm types. {{?I-D.ietf-pquip-pqt-hybrid-terminology}} defines the terminology for the Post-Quantum and Traditional Hybrid Schemes.

## PQ/T Hybrid Confidentiality 

The PQ/T Hybrid Confidentiality property can be used to protect from a "Harvest Now, Decrypt Later" attack, which refers to an attacker collecting encrypted data now and waiting for quantum computers to become powerful enough to break the encryption later. For example, in {{?I-D.ietf-tls-hybrid-design}}, the client uses the TLS supported groups extension to advertise support for a PQ/T hybrid scheme, and the server can select this group if it supports the scheme. The hybrid-aware client and server establish a hybrid secret by concatenating the two shared secrets, which is used as the shared secret in the existing TLS 1.3 key schedule.

## PQ/T Hybrid Authentication 

The PQ/T Hybrid Authentication property can be utilized in scenarios where an on-path attacker possesses network devices equipped with CRQCs, capable of breaking traditional authentication protocols. This property ensures authentication through a PQ/T hybrid scheme or a PQ/T hybrid protocol, as long as at least one component algorithm remains secure to provide the intended security level. For instance, a PQ/T hybrid certificate can be employed to facilitate a PQ/T hybrid authentication protocol. However, a PQ/T hybrid authentication protocol does not need to use a PQ/T hybrid certificate {{?I-D.ounsworth-pq-composite-keys}}; separate certificates could be used for individual component algorithms {{?I-D.ietf-lamps-cert-binding-for-multi-auth}}.

The frequency and duration of system upgrades and the time when CRQCs will become widely available need to be weighed in to determine whether and when to support the PQ/T Hybrid Authentication property.

# Security Considerations

Several PQC schemes are available that need to be tested; cryptography experts around the world are pushing for the best possible solutions, and the first standards that will ease the introduction of PQC are being prepared. It is of paramount importance and a call for imminent action for organizations, bodies, and enterprises to start evaluating their cryptographic agility, assess the complexity of implementing PQC into their products, processes, and systems, and develop a migration plan that achieves their security goals to the best possible extent.

# Further Reading & Resources

## Reading List
(A reading list. [Serious Cryptography](https://nostarch.com/seriouscrypto). Pointers to PQC sites with good explanations. List of reasonable Wikipedia pages.)

## Developer Resources

- [Open Quantum Safe](https://openquantumsafe.org/) and corresponding [github](https://github.com/open-quantum-safe)

# Acknowledgements
{:numbered="false"}

It leverages text from https://github.com/paulehoffman/post-quantum-for-engineers/blob/main/pqc-for-engineers.md. Thanks to Dan Wing and Florence D for the discussion and comments.
