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
     



--- abstract

The presence of a quantum computer would render state-of-the-art, public-key cryptography deployed today obsolete, since all the assumptions about the intractability of the mathematical problems that offer confident levels of security today no longer apply in the presence of a quantum computer.  Fortunately, research has produced several post-quantum cryptographic algorithms that will enable cryptography to survive the quantum world. However, the transition to a post-quantum infrastructure is not that straightforward and there are many things yet to be done. It is now a combination of engineering, pro-active assessment and evaluation of the available technologies, as well as careful product development approach, to pave a way to transit to the post quantum era.

--- middle

# Introduction

Quantum computing is no longer perceived as a conjecture of computational sciences and theoretical physics. Considerable research efforts and enormous corporate and government funding for the development of practical quantum computing systems are being invested currently. For instance, Google’s announcement on achieving quantum supremacy {{Google}} and IBM’s latest 433-qubit processor Osprey {{IBM}} signify, among other outcomes, the accelerating efforts towards large-scale quantum computers. The existence of a fault tolerant quantum computer would mark a cornerstone in mankind’s technological evolution, as it would mean that computational problems which are considered currently intractable for conventional computers would be tractable for quantum ones.

This document is meant to give general guidance on the structure and use of post-quantum cryptographic (PQC) algorithms for engineers who are using PQC algorithms in their software.
Topics include which PQC algorithms to use, how PQC key exchange mechanisms (KEMs) differ from classical KEMs, expected size and processing time differences between PQC algorithms and classical algorithms, as well as guidelines on the evolving threat landscape of symmetric cryptography from quantum computers.

The reader of this document is expected to understand coding and data structures using established cryptographic libraries. They are also expected to understand the basics of classical cryptography. It is also crucial for the reader to understand that when the word "PQC" is mentioned in the document, it usually means Asymmetric Cryptography in general and not any algorithms from the Symmetric side based on stream, block ciphers, etc.
It does not cover such topics as when classical algorithms might become vulnerable (for that, see documents such as [QC-DNS] and others).

# Conventions and Definitions

{::boilerplate bcp14-tagged}
The definitions section would be too exhaustive and what readers are already expected to be aware of as the suggested algorithms cover more or less the entire dimension of classical cryptography's mathematics. Nevertheless, the basics of lattices (hardness of SIVP, SIS), learning with errors (Ring/Module), coding theory (Goppa/LDPC/MDPC), basics of quantum computing (qubit,superposition theory, toffoli, CNOT, Hadamard gates, Grover's search attack, Shor's algorithm), multivariate cryptography (elliptic curves, diffie hellman), hashes are some of the definitions that might help get a quick understanding of the document.

Please note: This document does not go into the deep mathematics of the NIST finalists or other Post quantum algorithms but rather provides an overview to Engineers on the current threat landscape and the relevant algorithms designed to help prevent those threats.

# Contributing to This Document

The guide was inspired by a thread in September 2022 on the <mailto:pqc@ietf.org> mailing list.
The document is being collaborated on through a [GitHub repository](https://github.com/paulehoffman/post-quantum-for-engineers).

The editors actively encourage contributions to this document.
Please consider writing a section on a topic that you think is missing.
Short of that, writing a paragraph or two on an issue you found when writing code that uses PQC would make this document more useful to other coders.
Opening issues that suggest new material is fine too, but relying on others to write the first draft of such material is much less likely to happen than if you take a stab at it yourself.



# Classical Cryptographic Primitives that Could Be Replaced by PQC

* KEMs: They are one of the mechanisms that can replaced by PQC as this is based on public key cryptography and is therefore vulnerable to the Shor's algorithm. One, can easily find the prime factors of the large public key which can used to derive the private key.

* Signatures: Signatures, similar to KEMs also depend on public-private key pair and hence a break in public key cryptography will also affect classical digital signatures, hence the importance of developing post quantum digital signatures.

# Popular PQC Algorithms

The National Institute of Standards and Technology (NIST) started a process to solicit, evaluate, and standardize one or more quantum-resistant public-key cryptographic algorithms, as seen [here](https://csrc.nist.gov/projects/post-quantum-cryptography).
Said process has reached its [first announcement](https://csrc.nist.gov/publications/detail/nistir/8413/final) in July 5, 2022, which stated which candidates to be standardized for two types of algorithms:

* Key Encapsulation Mechanisms (KEMs): CRYSTALS-KYBER
* Digital Signatures: CRYSTALS-Dilithium, FALCON, SPHINCS+ 

NIST announced as well that they will be [opening a fourth round](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/guidelines-for-submitting-tweaks-fourth-round.pdf) to standardize an alternative KEM, and a [call](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/call-for-proposals-dig-sig-sept-2022.pdf) for new candidates for a post-quantum signature algorithm.

# Classic vs. Post-Quantum

Post-quantum cryptography or quantum-safe cryptography refers to cryptographic algorithms that are secure against cryptographic attacks from both a quantum and a classic computers.

When considering the security risks associated with the ability of a quantum computer to attack classic cryptography it is important to distinguish between the impact on symmetric algorithms and public-key ones. Professor Peter Shor and computer scientist Lov Grover developed two algorithms that were about to change the way the world thinks of security under the presence of a quantum computer. 

## Symmetric cryptography

Grover’s algorithm theoretically requires to double the key sizes of the algorithms that one deploys today to achieve quantum resistance. This is because Grover’s algorithm reduces the amount of operations to break 128-bit symmetric cryptography to 2^{64} quantum operations, which might sound computationally feasible. However, 2^{64} operations performed in parallel are feasible for modern classical computers, but 2^{64} quantum operations performed serially in a quantum computer are not. Grover's algorithm is highly non-parallelisable and even if one deploys 2^c computational units in parallel to brute-force a key using Grover's algorithm, it will complete in time proportional to 2^{(128−c)/2}, or, put simply, using 256 quantum computers will only reduce runtime by 1/16, 1024 quantum computers will only reduce runtime by 1/32 and so forth ​(see {{NIST}} and {{Cloudflare}}​).  

How can someone be sure then that an improved algorithm won’t outperform Grover's algorithm at some point in time? Christof Zalka has shown that Grover's algorithm (and in particular its non-parallel nature) achieves the best possible complexity for unstructured search {{Grover-search}}.

Finally, in their evaluation criteria for PQC, NIST is considering a security level equivalent to that of AES-128, meaning that NIST has confidence in standardizing parameters for PQC that offer similar levels of security as AES-128 does {{NIST}}​. As a result, 128-bit algorithms should be considered quantum-safe for many years to come. 


## Asymmetric cryptography

“Shor’s algorithm” on the other side, efficiently solves the integer factorization problem (and the equivalent discrete logarithm problem), which offer the foundations of the public-key cryptography that the world uses today. This implies that, if a practical quantum computer was developed, much of today’s public-key cryptography algorithms (e.g., RSA, Diffie-Hellman and Elliptic Curve Cryptography - ECC) and the accompanying digital signatures schemes and protocols would need to be replaced by algorithms and protocols that can offer cryptanalytic resistance against quantum computers.  

For unstructured data such as symmetric encrypted data or cryptographic hashes, although quantum computers can search for specific solutions across all possible input combinations (e.g., Grover's Algorithm), no quantum algorithm is known to completely break the security properties of these classes of algorithms

For structured data such as public-key and signatures, instead, quantum computers can fully solve the underlying hard problems used in classic cryptography (see Shor's Algorithm). Because an increase of the size of the keypair would not provide a secure solution in this case, a complete replacement of the algorithm is needed. Therefore, post-quantum public-key cryptography must rely on problems that are different from the ones used in classic public-key cryptography (i.e., the integer factorization problem, the discrete logarithm problem, and the elliptic-curve discrete logarithm problem). 


# Pervasive Monitoring

An malicious actor with adequate resources may be lauching a pervasive monitoring (PM) attack to store sensitive encrypted data today that can be decrypted once a quantum computer is available. This implies that, every day sensitive encrypted data is suspetible to PM attack by not implementing quantum-safe strategies, as it corresponds to data being deciphered in the future.  

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

These challenges are illustrated nicely by the so called Mosca model discussed in ​{{Threat-Report}}. In the {{Mosca}}, "x" denotes the time that our systems and data need to remain secure, "y" the number of years to migrate to a PQC infrastructure and "z" the time until a practical quantum computer that can break current cryptography is available. The model assumes that encrypted data can be intercepted and stored before the migration is completed in "y" years. This data remains vulnerable for the complete "x" years of their lifetime, thus the sum "x+y" gives us an estimate of the full timeframe that data remain insecure​. The model essentially asks the question of how are we preparing our IT systems during those "y" years (or in other words how can one minimize those "y" years), so as to minimize the transition phase to a PQC infrastructure and hence minimize the risks of data being exposed in the future. 

Finally, other factors that could accelerate the introduction of a large-enough quantum computer should not be under-estimated, like for example faster-than-expected advances in quantum computing and more efficient versions of Shor’s algorithm requiring less qubits. As an example, IBM, one of the leading actors in the development of a large-scale quantum computer, has recently published a roadmap committing to new quantum processors supporting more than 1000 qubits by 2025 and networked systems with 10k-100k qubits beyond 2026 {{IBMRoadmap}}. Innovation often comes in waves, so it is to the industry’s benefit to remain vigilant and prepare as early as possible. 

# Post-quantum cryptography categories 

The current set of problems used in post-quantum cryptography can be currently grouped into five different categories: multivariate, lattice-based, code-based, hash-based, and the isogeny-based.

## Lattice-Based Public-Key Cryptography

Lattice-based public-key cryptography leverages the simple construction of lattices (i.e., a regular collection of points in an Euclidean space that are regularly spaced) to build problems that are hard to solve such as the Shortest Vector or Closes Vector Problem, Learning with Errors, and Learning with Rounding. All these problems have good proof for worst-to-average case reduction, thus equating the hardness of the average case to the worst-case.

The possibility to implement public-key schemes on lattices is tied to the characteristics of the basis used for the lattice. In particular, solving any of the mentioned problems can be easy when using reduced or "good" basis (i.e., as short as possible and as orthogonal as possible), while it becomes computationally infeasible when using "bad" basis (i.e., long vectors not orthogonal). Although the problem might seem trivial, it is computationally hard when considering many dimensions. Therefore a typical approach is to use use "bad" basis for public keys and "good" basis for private keys. The public keys ("bad" basis) let you easily verify signatures by checking, for example, that a vector is the closest or smallest, but do not let you solve the problem (i.e., finding the vector). Conversely, private keys (i.e., the "good" basis) can be used for generating the signatures (e.g., finding the specific vector). Signing is equivalent of solving the lattice problem.

Lattice-based schemes usually have good performances and average size public keys and signatures making them good candidates for general-purpose use such as replacing the use of RSA in PKIX certificates.

Examples of such class of algorithms are Falcon and Dilithium.

## Multivariate-Based Public-Key Cryptography

The Multivariate Quadratic problem is an NP-hard problem that can be expressed as finding the common "zero" vector that solves a set of polynomials in finite fields. In other words, the underlying problem can be expressed as finding the vector (z_1, ..., z_n) in Fn2 that solves a set of given equations:

f_{1}(x_{1}, ..., x_{n}) = 0, ...., f_{m}(x_{1}, ..., x_{n}) = 0

Signatures use easily invertible non-linear polynomials (P) that need to be masked by using a combination of affine linear transformations (S and T). Indeed, given P:Fn -> Fm, S: Fn -> Fn, T: Fm -> Fm, the affine transformations are build in such a way to make the public key G = S * P * T hard to invert. Knowing its individual components (i.e., the private key) allows to easily compute the inverse G^(-1) which is used to produce signatures, i.e. G^(-1) = T^(-1) * P^(-1) * S^(-1). To verify signatures, use the public key over the signature vector, i.e. G(s) = m.

## Code-Based Public-Key Cryptography

## Hash-Based Public-Key Cryptography

## Isogeny-Based Public-Key Cryptography

## Announced to be standardized NIST algorithms

# PQC KEMs

* [CRYSTALS-Kyber](https://pq-crystals.org/kyber/): Kyber is a module learning with errors (MLWE)-based key encapsulation mechanism.

# PQC Signatures

* [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)
* [Falcon](https://falcon-sign.info/)
* [SPHINCS+](https://sphincs.org/)

# Candidates advancing to the fourth-round for standardization at NIST

The fourth-round of the NIST process only concerns with KEMs.
The candidates still advancing for standardization are:

* [Classic McEliece](https://classic.mceliece.org/)
* [BIKE](https://bikesuite.org/)
* [HQC](http://pqc-hqc.org/)
* [SIKE](https://sike.org/) (Broken): Supersingular Isogeny Key Encapsulation (SIKE) is a specific realization of the SIDH (Supersingular Isogeny Diffie-Hellman) protocol. Recently, a [mathematical attack](https://eprint.iacr.org/2022/975.pdf) based on the "glue-and-split" theorem from 1997 from Ernst Kani was found against the underlying chosen starting curve and torsion information. In practical terms, this attack allows for the efficient recovery of the private key. NIST has to yet comment if the scheme will be still considered and there is still debate around if the scheme can be changed so that the attack can be prevented.

# Algorithms not-to-be standardized by NIST that have some support

* [NTRU](https://ntru.org/)
* [NTRU-Prime](https://ntruprime.cr.yp.to/)


# KEMs

## What is a KEM

KEM stands for Key Encapsulation Mechanism (stated above) and as the name suggests it is used to protect symmetric keys that encrypt user data ideally by encapsulating the shared secret symmetric key and transmitting it via asymmetric cryptography. This is done to provide faster encryption/decryption speeds. Prior art dictates that public key systems tend to be generate high costs when encrypting longer messages than symmetric key systems. Hence, in this best of both worlds scenario, one uses the symmetric key to encrypt the message first, following which the public key of the sender is used to encrypt the symmetric key. The receiver then first decrypts the ciphertext using their private keys to gain the symmetric key, finally that symmetric key is leveraged to generate the plaintext.

## What security properties do they provide

* IND-CPA : Bike provides IND-CPA security generally but can also be used to provide IND-CCA security.
* IND-CCA : Kyber, Classic McEliece, Saber provide IND-CCA2 security.

## Where can a KEM be used

To note:
* KEMs vs Diffie-Hellman (DH): they can be a replacement but they are not a one-to-one replacement. KEMs do not provide non-interactivity, for example, that DH does provide.
* Replacing DH algorithms with PQ KEMs.
* Which are used where.
* “Key Transport API (aka RSA)”, the “Key Agreement API (aka (EC)DH)”, and how the “KEM API” is neither of those.

# PQC Signatures

## What is a Post-quantum Signature

## What security properties do they provide

* EUF-CMA : Dilithium provides EUF-CMA security.

## Where can different types of PQC signatures be used

(HBS vs Lattice signatures: when each is appropriate.)

(Guidance for managing state of XMSS / LMS. Tree-splitting at keygen time, synchronous state management, any other tricks that are worth documenting. Including when it’s just too complicated to even attempt, like a 30 year signing key where you don’t know at keygen time how many backup copies you’ll need over its lifetime and flips to backup may happen without warning.)

## Recommendations for Security / Performance Tradeoffs

(For example if full-strength Kyber1024 just won’t fit. Under what circumstances can you go down to level1 lattice strength (or less)?)
The table below denotes the 5 security levels provided by NIST required for PQC algoritms. Users can leverage the required algorithm based on the security level based on their use case. The security is defined as a function of resources required to break AES and SHA3 algorithms, i.e., optimal key recovery for AES and optimal collision attacks for SHA3.

| Security Level |            AES/SHA3 hardness       | PQC Algorithm |
| -------------- | ---------------------------------- | ------------- |
|       1        | Find optimal key in AES-128        |   Kyber512    |
|       2        | Find optimal collision in SHA3-256 |   Dilithium2  |
|       3        | Find optimal key in AES-192        |   Kyber768    |
|       4        | Find optimal collision in SHA3-384 |       N/A     |
|       5        | Find optimal key in AES-256        |   Kyber1024   |

## Details of FALCON and Dilithium 

Falcon [Falcon] is based on the GPV hash-and-sign lattice-based
signature framework introduced by Gentry, Peikert and Vaikuntanathan,
which is a framework that requires a class of lattices and a
trapdoor sampler technique. 

The main design principle of Falcon is compactness, i.e. it was
designed in a way that achieves minimal total memory bandwidth
requirement (the sum of the signature size plus the public key size).
This is possible due to the compactness of NTRU lattices.  Falcon
also offers very efficient signing and verification procedures.  The
main potential downsides of Falcon refer to the non-triviality of its
algorithms and the need for floating point arithmetic support.

Access to a robust floating-point stack in Falcon is essential 
for accurate, efficient, and secure execution of the 
mathematical computations involved in the scheme. It helps 
maintain precision, supports error correction techniques, 
and contributes to the overall reliability and performance 
of Falcon's cryptographic operations.

The performance characteristics of Dilithium and Falcon may 
differ based on the specific implementation and hardware platform. 
Generally, Dilithium is known for its relatively fast signature 
generation, while Falcon can provide more efficient 
signature verification. The choice may depend on whether 
the application requires more frequent signature generation 
or signature verification.


## Hash-then-Sign Versus Sign-then-Hash

Within the hash-then-sign paradigm, the message is hashed before signing it.  Hashing the message before signing it provides an additional layer of security by ensuring that only a fixed-size digest of the message is signed, rather than the entire message itself. By pre-hashing, the onus of resistance to existential forgeries becomes heavily reliant on the collision-resistance of the hash function in use.  As well as this security goal, the hash-then-sign paradigm also has the ability to improve performance by reducing the size of signed messages.  As a corollary, hashing remains mandatory even for short messages and assigns a further computational requirement onto the verifier.  This makes the performance of hash-then-sign schemes more consistent, but not necessarily more efficient. Using a hash function to produce a fixed-size digest of a message ensures that the signature is compatible with a wide range of systems and protocols, regardless of the specific message size or format.

# Post-Quantum and Traditional Hybrid Schemes

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor
the post-quantum algorithms are fully trusted to protect data for the required data lifetimes.  The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying
mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there may be a desire or a requirement for protocols that use both algorithm types. {{?I-D.ietf-pquip-pqt-hybrid-terminology}} defines terminology for the Post-Quantum and Traditional Hybrid Schemes.

## PQ/T Hybrid Confidentiality 

The PQ/T Hybrid Confidentiality scheme is required to protect from a "Harvest Now, Decrypt Later" attack, which refers to an attacker collecting encrypted data now and waiting for quantum computers to become powerful enough to break the encryption later. For example, in {{?I-D.ietf-tls-hybrid-design}}, the client uses the TLS supported groups extension to advertise support for a PQ/T hybrid scheme and the server can select this group if it supports the scheme. The hybrid-aware client and server establish a hybrid secret by concatenating the two shared secrets and it used as the shared secret 
in the existing TLS 1.3 key schedule.

## PQ/T Hybrid Authentication 

The PQ/T Hybrid Authentication scheme is required where an on-path attacker can use network devices with quantum processors to break
the traditional authentication protocols. In this scheme, authentication is achieved by a PQ/T hybrid scheme or a PQ/T hybrid protocol as long as at least one component algorithm that aims to provide this property remains secure. For example, a PQ/T hybrid certificate could be used to facilitate a PQ/T hybrid authentication protocol.  However, a PQ/T hybrid authentication protocol does not need to use a PQ/T hybrid certificate {{?I-D.ounsworth-pq-composite-keys}}; separate certificates could be used for individual component algorithms {{?I-D.ietf-lamps-cert-binding-for-multi-auth}}.

The frequency and duration of system upgrades and the time when quantum computers will become widely available needs to be weighed in to determine when to support the PQ/T Hybrid Authentication scheme.

# Security Considerations

A quantum-world is deﬁnitely not as intimidating as one might expect from a security standpoint. Several PQC schemes are available which needs to be tested, cryptography experts around the world are pushing for the best possible solutions and the first standards that will ease the introduction of PQC are being prepared. It is of paramount importance and a call for imminent action for organizations, bodies, and enterprises, to start evaluating their cryptographic agility, assess the complexity of implementing PQC into their products, processes, and systems, and develop a migration plan that achieves their security goals in the best possible extent.

# Further Reading & Resources

## Reading List
(A reading list. [Serious Cryptography](https://nostarch.com/seriouscrypto). Pointers to PQC sites with good explanations. List of reasonable Wikipedia pages.)

## Developer Resources

- [Open Quantum Safe](https://openquantumsafe.org/) and corresponding [github](https://github.com/open-quantum-safe)

# Acknowledgements
{:numbered="false"}

It leverages text from https://github.com/paulehoffman/post-quantum-for-engineers/blob/main/pqc-for-engineers.md.
