---
title: "Adapting HSMs for Post-Quantum Cryptography"
abbrev: "Adapting HSMs for PQC"
category: info

docname: draft-reddy-pquip-pqc-hsm-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "PQUIP"
keyword:
 - PQC
 - HSM


venue:
  group: "pquip"
  type: "Working Group"
  mail: "pqc@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/pqc/"


stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
 -
    fullname: Dan Wing
    organization: Cloud Software Group Holdings, Inc.
    abbrev: Cloud Software Group
    country: United States of America
    email: danwing@gmail.com
 -
    fullname: Ben Salter
    organization: UK National Cyber Security Centre
    email: ben.s3@ncsc.gov.uk

normative:

informative:
  RFC8554:
  RFC8391:
  ML-KEM:
     title: "FIPS-203: Module-Lattice-based Key-Encapsulation Mechanism Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
     date: false
  ML-DSA:
     title: "FIPS-204: Module-Lattice-Based Digital Signature Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
     date: false
  REC-SHS:
     title: "Recommendation for Stateful Hash-Based Signature Scheme"
     target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-208.pdf
     date: false
  BIND:
    title: Unbindable Kemmy Schmid
    target: https://eprint.iacr.org/2024/523.pdf
  SLH-DSA:
     title: "FIPS-205: Stateless Hash-Based Digital Signature Standard"
     target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
     date: false
  REC-KEM:
    title: Recommendations for Key-Encapsulation Mechanisms
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-227.ipd.pdf

--- abstract


Hardware Security Modules (HSMs) play a critical role in securing cryptographic operations, including the adoption of Post-Quantum
Cryptography (PQC). This document examines the use of seed-based key generation in HSMs, which reduces storage requirements but increases
computational overhead for key derivation. It explores trade-offs between storage efficiency and performance, addressing challenges in
ephemeral key handling and optimization strategies for PQC signature algorithms. It also discusses PQC impacts to HSM firmware updates and
backup.

--- middle

# Introduction

The transition to post-quantum cryptography (PQC) introduces new challenges for cryptographic key management, particularly within constrained Hardware Security Modules (HSMs). Unlike high-performance, rack-mounted HSMs, constrained HSMs operate with limited memory, storage, and computational resources, making the adoption of PQC algorithms more challenging. The increased key sizes and computational demands of PQC require careful consideration to ensure secure and efficient key management within these constrained environments.

This document provides industry guidance and best practices for integrating PQC algorithms into constrained HSMs. It explores key storage strategies, ephemeral key management, and performance optimizations specific to resource-limited environments. One approach to mitigating storage constraints is seed-based key generation, where only a small seed is stored instead of the full private key, as supported by PQC schemes like ML-DSA and SLH-DSA. However, this technique increases computational overhead due to the need to derive full private keys on demand. The document also discusses considerations for ephemeral key generation in protocols like TLS and IPsec, along with techniques to optimize PQC signature operations to enhance performance within constrained HSMs.

This document focuses on the use of PQC algorithms in HSMs, specifically the three algorithms finalized by NIST: ML-DSA, ML-KEM, and SLH-DSA. While other PQC algorithms, such as stateful hash-based signatures, also provide post-quantum security, they are not covered in this version of the document. Future revisions may expand the scope to include additional PQC algorithms.

# Key Management in HSMs for PQC

One mitigation of storage limitations is to store only the seed rather than the full expanded private key, as the seed is far smaller and can derive the expanded private key as necessary.

## Seed Management {#Seed}

The seed generated during the PQC key generation function is highly sensitive, as it will be used to compute the private key or decapsulation key. Consequently, seeds must be treated with the same level of security as private keys.

To comply with {{ML-KEM}}, {{ML-DSA}}, {{SLH-DSA}} and {{REC-KEM}} guidelines:

### Seed Storage

   Seeds must be securely stored within a cryptographic module, such as a Hardware Security Module (HSM), to ensure protection against unauthorized access. Since the seed can be used to compute the private key, it must be safeguarded with the same level of protection as the private key itself. For example, according to {{ML-DSA}} Section 3.6.3, the seed `ξ` generated during `ML-DSA.KeyGen` can be stored for later expansion using `ML-DSA.KeyGen_internal`.

   The choice between storing a seed or an expanded private key involves trade-offs between storage efficiency and performance. Some constrained HSMs may store only the seed and derive the expanded private key on demand, whereas others may prefer storing the full expanded key to reduce computational overhead during key usage. 
   
   While vulnerabilities like the "Unbindable Kemmy Schmidt" attack {{BIND}} demonstrate the risks of manipulating expanded private keys in certain non-HSM environments, these attacks generally assume an adversary has some level of control over the expanded key format. However, in a HSM environment, where private keys are typically protected from such manipulation, the primary motivation for storing the seed rather than the expanded key is not directly tied to mitigating "Kemmy" attacks.

   The ML-DSA and ML-KEM private key formats, as specified in {{?I-D.ietf-lamps-dilithium-certificates}} and {{?I-D.ietf-lamps-kyber-certificates}}, represent the private key using a seed from which the expanded private key is derived. While these formats rely on the seed for key generation, an HSM may choose to store the expanded private key to avoid the additional computation required for running KeyGen. HSM implementations must also consider compatibility with existing standards such as PKCS#11.

   This choice between storing the seed or the expanded private key has direct implications on performance, as key derivation incurs additional computation. The impact of this overhead varies depending on the algorithm. For instance, ML-DSA key generation, which primarily involves polynomial operations using the Number Theoretic Transform (NTT) and hashing, is computationally efficient. In contrast, SLH-DSA key generation requires constructing a Merkle tree and multiple calls to Winternitz One-Time Signature (WOTS+) key generation, making it significantly slower due to the recursive hash computations involved. HSM designers must carefully balance storage efficiency and computational overhead based on system requirements and operational constraints. While HSMs employ various key storage strategies, the decision to store full private keys or only seeds depends on design goals, performance considerations, and standards compliance.

   A key challenge arises when importing an existing private key into a system designed to store only seeds. When a user attempts to import an already expanded private key, there is a mismatch between the key format used internally (seed-based) and the expanded private key. This issue arises because the internal format is designed for efficient key storage by deriving the private key from the seed, while the expanded private key is already fully computed. As NIST has not defined a single private key format for PQC algorithms, this creates a potential gap in interoperability.

   If the seed is not securely stored at the time of key generation, it is permanently lost because the process of deriving an expanded key from the seed relies on a one-way cryptographic function. This one-way function is designed to ensure that the expanded private key can be deterministically derived from the seed, but the reverse operation, deriving the original seed from the expanded key is computationally infeasible.

### Efficient Key Derivation

   When storing only the seed in an HSM, it is crucial that the HSM is capable of deriving the private key efficiently whenever required. However, it is important to note that constantly re-deriving the private key for every cryptographic operation may introduce significant performance overhead. In scenarios where performance is a critical consideration, it may be more efficient to store the expanded private key directly instead of only the seed.

   The key derivation process, such as ML-KEM.KeyGen_internal for ML-KEM or similar functions for other PQC algorithms, must still be implemented in a way that can securely operate within the resource constraints of the HSM. If using the seed-only model, the derived private key should only be temporarily held in memory during the cryptographic operation and discarded immediately after use. However, storing the expanded private key may be a more practical solution in some scenarios and could be considered for optimization.

### Secure Exporting of Seeds

   Given the potential for hardware failures or the end-of-life of HSM devices, it is essential to plan for backup and recovery of the cryptographic seeds. HSMs should support secure seed backup mechanisms, ideally leveraging encrypted storage and ensuring that the backup data is protected from unauthorized access. In a disaster recovery scenario, the seed should be recoverable to enable the re-derivation of the private key, provided the proper security measures are in place to prevent unauthorized extraction.
   For secure exporting of seeds, PQC encryption algorithms, such as ML-KEM, should be used to encrypt the seed before export. This ensures that the seed remains protected even if the export process is vulnerable to quantum attacks. The process for secure export should include:

   - Encrypting the seed using a post-quantum encryption algorithm, such as ML-KEM, rather than relying on traditional encryption algorithms.
   - Ensuring the exported seed is accessible only to authorized entities.
   - Enforcing strict access controls and secure transport mechanisms to prevent unauthorized access during transfer.

Wherever possible, seed generation, storage, and usage should remain entirely within the cryptographic module. This minimizes the risk of exposure and ensures compliance with established security guidelines.

# Ephemeral Key Management

In protocols like TLS and IPsec, ephemeral keys are used for key exchange. Given the increased size of PQC key material, ephemeral key management will have to be optimized for both security and performance.

For PQC KEMs, ephemeral key-pairs must be generated from an ephemeral seed, which needs to be securely stored temporarily and erased after use. This approach ensures that ephemeral key generation is deterministic and minimizes storage overhead in HSMs, as only the seed (not the full private key) needs to be stored. The ephemeral seed must be deleted immediately after the key pair is generated to prevent potential leakage or misuse.

Furthermore, once the shared secret is derived, the private key must also be deleted. Since the private key resides in the HSM, removing it optimizes memory usage, reducing the footprint of PQC key material in constrained HSMs.

Additionally, ephemeral keys should not be reused across different algorithm suites and sessions. Each ephemeral key-pair must be uniquely associated with a specific key exchange instance to prevent cryptographic vulnerabilities, such as cross-protocol attacks or unintended key reuse.

HSMs implementing PQC ephemeral key management will have to:

  * Generate ephemeral key-pairs on-demand from an ephemeral seed stored temporarily within the cryptographic module.
  * Enforce immediate seed erasure after the key-pair is generated and the cryptographic operation is completed.
  * Delete the private key after the shared secret is derived.
  * Prevent key reuse across different algorithm suites or sessions.

# Optimizing Performance in Hardware Implementations of PQC Signature Algorithms

When implementing PQC signature algorithms in hardware devices, such as Hardware Security Modules (HSMs), performance optimization becomes a critical consideration. Transmitting the entire message to the HSM for signing can lead to significant overhead, especially for large payloads. To address this, implementers can leverage techniques that reduce the data transmitted to the HSM, thereby improving efficiency and scalability.

One effective approach involves sending only a message digest to the HSM for signing. By signing the digest of the content rather than the entire content, the communication between the application and the HSM is minimized, enabling better performance. This method is applicable for any PQC signature algorithm, whether it is ML-DSA, SLH-DSA, or any future signature scheme. For such algorithms, a mechanism is often provided to pre-hash or process the message in a way that avoids sending the entire raw message for signing. In particular, algorithms like SLH-DSA present challenges due to their construction, which requires multiple passes over the message digest during the signing process. The signer does not retain the entire message or its full digest in memory at once. Instead, different parts of the message digest are processed sequentially during the signing procedure. This differs from traditional algorithms like RSA or ECDSA, which allow for more efficient processing of the message, without requiring multiple passes or intermediate processing of the digest.

A key consideration when deploying ML-DSA in HSMs is the amount of RAM available. ML-DSA, unlike traditional signature schemes such as RSA or ECDSA, requires significant memory during signing due to multiple Number Theoretic Transform (NTT) operations, matrix expansions, and rejection sampling loops. These steps involve storing large polynomial vectors and intermediate values, making ML-DSA more memory-intensive. If an HSM has sufficient RAM, this may not be an issue. However, in constrained environments with limited RAM, implementing ML-DSA can be challenging. The signer must store and process multiple transformed values, leading to increased computational overhead if the HSM lacks the necessary RAM to manage these operations efficiently.

To address the memory consumption challenge, algorithms like ML-DSA offer a form of pre-hash using the mu (message representative) value described in Section 6.2 of {{ML-DSA}}. The mu value provides an abstraction for pre-hashing by allowing the hash or message representative to be computed outside the HSM. This feature offers additional flexibility by enabling the use of different cryptographic modules for the pre-hashing step, reducing RAM consumption within the HSM. The pre-computed mu value is then supplied to the HSM, eliminating the need to transmit the entire message for signing. {{?I-D.ietf-lamps-dilithium-certificates}} discusses leveraging ExternalMu-ML-DSA, where the pre-hashing step (ExternalMu-ML-DSA.Prehash) is performed in a software cryptographic module, and only the pre-hashed message (mu) is sent to the HSM for signing (ExternalMu-ML-DSA.Sign).
By implementing ExternalMu-ML-DSA.Prehash in software and ExternalMu-ML-DSA.Sign in an HSM, the cryptographic workload is efficiently distributed, making it practical for high-volume signing operations even in memory-constrained HSM environments.

# Additional Considerations for HSM Use in PQC

Key Rotation and Renewal: Applications are responsible for managing key lifecycles, including periodic key rotation and renewal, for compliance and cryptographic agility. While an HSM may provide mechanisms to facilitate secure key rotation, such as generating new key pairs, securely storing new seeds, and securely deleting outdated keys, this functionality is not necessarily specific to PQC. However, the security of PQC schemes is subject to ongoing research and potential cryptanalytic advances. Future developments in quantum algorithms, improved attacks on lattice-based cryptography, or side-channel vulnerabilities may necessitate adjustments to key sizes, algorithm choices and key rotation policies. HSMs should be designed to support flexible key management, including the ability to update algorithms and parameters as new security recommendations emerge.

# Post-quantum Firmware Upgrades for HSMs

HSMs deployed in the field require periodic firmware upgrades to patch security vulnerabilities, introduce new cryptographic algorithms, and improve overall functionality. However, the firmware upgrade process itself can become a critical attack vector if not designed to be post-quantum. If an adversary compromises the update mechanism, they could introduce malicious firmware, undermining all other security properties of the HSM. Therefore, ensuring a post-quantum firmware upgrade process is critical for the security of deployed HSMs.

CRQCs pose an additional risk by breaking traditional digital signatures (e.g., RSA, ECDSA) used to authenticate firmware updates. If firmware verification relies on traditional signature algorithms, attackers could generate forged signatures in the future and distribute malicious updates.

## Post-quantum Firmware Authentication

To ensure the integrity and authenticity of firmware updates, HSM vendors will have to adopt PQC digital signature schemes for code signing. Recommended post-quantum algorithms include:

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm): SLH-DSA does not introduce any new hardness assumptions beyond those inherent to its underlying hash functions. It builds upon established foundations in cryptography, making it a reliable and robust digital signature scheme for a post-quantum world. While attacks on lattice-based schemes like ML-DSA can compromise their security, SLH-DSA will remain unaffected by these attacks due to its distinct mathematical foundations. This ensures the ongoing security of systems and protocols that use SLH-DSA for digital signatures. Given that the first vulnerabilities in PQC algorithms are more likely to arise from implementation flaws rather than fundamental mathematical weaknesses, SLH-DSA is still susceptible to attacks if not properly implemented..

HSS-LMS (Hierarchical Signature System - Leighton-Micali Signature): A hash-based signature scheme, providing long-term security and efficient key management for firmware authentication (see {{REC-SHS}}).

XMSS (eXtended Merkle Signature Scheme): Another stateful hash-based signature scheme similar to HSS-LMS {{RFC8391}}. XMSS signatures are slightly shorter than HSS-LMS signatures for equivalent security. However, HSS-LMS provides performance advantages and HSS-LMS is considered
simpler (see Section 10 of {{RFC8554}}).

Firmware images can be signed using one of these post-quantum algorithms before being distributed to HSMs. {{?I-D.wiggers-hbs-state}} discusses various strategies for a correct state and backup management for stateful hash-based signatures.

Firmware images often have a long lifetime, requiring cryptographic algorithms that provide strong security assurances over extended periods. ML-DSA is not included in this list because it is a lattice-based signature scheme, making it susceptible to potential advances in quantum and classical attacks on structured lattices. The long-term security of ML-DSA depends on the continued hardness of lattice-based problems, which remain an active area of research. In contrast, SLH-DSA, HSS-LMS, and XMSS are based on well-studied hash functions, ensuring their security does not rely on unproven assumptions about lattice hardness. Given this uncertainty, use of a hash-based signature such as SLH-DSA may be preferable to ML-DSA for firmware authentication, where cryptographic stability over a long lifetime is a critical requirement.

# Security Considerations

The security considerations for key management in HSMs for PQC focus on the secure storage and handling of cryptographic seeds, which are used to derive private keys. Seeds must be protected with the same security measures as private keys, and key derivation should be efficient and secure within resource-constrained HSMs. Secure export and backup mechanisms for seeds are essential to ensure recovery in case of hardware failure, but these processes must be encrypted and protected from unauthorized access.

## Side Channel Protection
Side-channel attacks exploit physical leaks during cryptographic operations, such as timing information, power consumption, electromagnetic emissions, or other physical characteristics, to extract sensitive data like private keys or seeds. Given the sensitivity of the seed and private key in PQC key generation, it is critical to consider side-channel protection in HSM design. While side-channel attacks remain an active research topic, their significance in secure hardware design cannot be understated. HSMs must incorporate strong countermeasures against side-channel vulnerabilities to prevent attackers from gaining insights into secret data during cryptographic operations.

# Acknowledgements
{:numbered="false"}

Thanks to Jean-Pierre Fiset, Richard Kettlewell, Mike Ounsworth, and Aritra Banerjee for the detailed review.
