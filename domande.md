# Domande e Risposte

## 1. Perfect Forward Secrecy

"What is perfect forward secrecy? What is the problem if the protocol does not have it? Show an example of implementation."

- Perfect Forward Secrecy is a property of a security protocol ensuring that the compromise of the long-term private key used for key exchange does not compromise past session keys. Consequently, a leak of the long-term secret only affects current and eventually future traffic, while past encrypted communications remain confidential.

If a protocol does not implement PFS, an attacker can record and store all encrypted traffic over time. If the attacker later obtains the server's long-term private key, they can decrypt every previously recorded session.

To achieve PFS, the protocol must transition from Key Transport to Key Agreement using Ephemeral Key Exchange such as DHE or ECDHE.

In the TLS implementation, for example, instead of using the server's static certificate key to encrypt a secret, the parties generate a one-time asymmetric key pair "on the fly" for each individual session. The procedural details are as follows:

- Since Temporary keys are not certified, the server sends its ephemeral public parameter, inside the Server Key Exchange message.
- The Server Key Exchange message is the only message in the handshake explicitly signed by the server's long-term private key to prove its identity to the client.
- The long-term private key is used exclusively for authentication, via signing, rather than confidentiality. If the long-term key is discovered, it leads to authentication failures but cannot be used to decrypt past records, as the ephemeral keys used for that traffic were never stored and have been deleted.

---

## 2. Authentication and Handshake

"Describe TLS client authentication: how it works, and its advantages and disadvantages. Specifically, discuss TLS 1.2 handshakes with ephemeral keys, distinguishing between scenarios with and without client authentication."

TLS Client Authentication is an optional mechanism that establishes mutual authentication, allowing both the server and the client to verify each other's identities.

During the handshake, the server sends a Certificate request message specifying the list of trusted CAs and the supported certificates. The client responds with its Certificate, that must be issued by a trusted CA and the Certificate Verify message. The Certificate Verify contains a signature computed over the hash of all the handshake messages before this one, proving that the client possesses the private key.

It provides mutual authentication and strong security, rejecting fake clients, but suffers from credential availability, because clients often lack certificates, management complexity because it requires a PKI and usability because browsers must show an user the list of all available certificates that match the trusted CAs.

### TLS 1.2 Handshake with Ephemeral keys

In TLS 1.2 the use of ephemeral keys such as DHE or ECDHE, is critical for achieving perfect forward secrecy, generating a one-time asymmetric key on the fly for the key exchange, rather than using its static long-term key for encryption.

#### Case 1: Ephemeral keys without client authentication

In this scenario, after the Client Hello and the Server Hello, the server sends its Certificate and the Server Key Exchange message. This message carries the signed RSA key or DH exponent, this is the only message explicitly signed by the server. The server is authenticated via this signature, while the client remains anonymous.

#### Case 2: Ephemeral keys with client authentication

In this scenario, the server sends the Server Key Exchange with signed ephemeral parameters like before but it is followed by the Certificate Request. The client responds with its Certificate, Client Key Exchange with its ephemeral key part and Certificate Verify where the client signs a hash of all the previous handshake messages before this one.

The server is authenticated via the signature on the Server Key Exchange and the client is authenticated via the signature on the Certificate Verify.

---

## 3. Sessions and Connections

"Explain the difference between TLS sessions and connections. What is their relationship, and specifically, what is the relationship between their keys?"

A TLS Session is a logical association between a client and a server. It is created by the Handshake Protocol and defines a set of cryptographic security parameters that can be reused to avoid the overhead of full handshakes.

In contrast, a TLS Connection is a transient TLS channel between the client and the server. While the session represents the agreed-upon security parameters, the connection represents the active communication link.

### Relationship between Sessions and Connections
The relationship is hierarchical (1:N), allowing for greater efficiency:

* **One-to-Many (1:N):** A single TLS session can be shared by one or more TLS connections.
* **One-to-One (1:1):** Every specific TLS connection is associated with exactly one TLS session.

### Relationship between the Keys
The security of this model relies on the distinction between long-term session secrets and short-term connection keys.

* **Session Secrets:** Every time a new session is established, a new Pre-Master Secret and a new Master Secret are generated. This Master Secret is persistent and common to all connections associated with that specific session.
* **Connection Keys:** Every time a new connection is opened within that session, new Client Random and Server Random values are exchanged.
* **Derivation:** These random values are used together with the persistent Master Secret to derive all the operative keys for that specific connection:
    * Keys for Message Authentication Code (MAC).
    * Keys for Encryption.
    * Initialization Vectors (IV).

This mechanism ensures that even if multiple connections share the same session context, the actual keys used for data protection are fresh and unique for every transmission.

---

## 4. TLS Browser solutions to verify a status of a certificate

"Discuss of TLS Browser solutions to verify a status of a certificate advantages e disadvantages (pushed CRLs, OCSP stapling, etc.)"

Browser-based solutions were developed to overcome the limitations of traditional revocation checking, such as privacy leaks and performance latency.

### Pushed CRLs
In this model, browser vendors identify revoked certificates, focusing on those originating from a compromised intermediate CA, and push these lists directly to the browser via software updates.

#### Advantages:
**Privacy:** The client does not contact the CA, preventing the CA from tracking which sites the user is visiting.
**Performance:** Eliminates the network latency required to fetch revocation data during the TLS handshake.
#### Disadvantages:
**Completeness:** Due to list size constraints, these sets only contain a fraction of all revoked certificates (usually focusing on high-impact intermediate CAs).
**Freshness:** The data is only as current as the last browser update.

### OCSP Stapling
OCSP Stapling is a TLS extension where the TLS server autonomously obtains the signed OCSP response from the CA and passes ("staples") it to the client along with its certificate during the handshake.

#### Advantages:
**Privacy:** The CA only sees the server's IP address making requests, not the individual clients' IP addresses.
**Performance:** The client receives the status immediately with the certificate, removing the need for an external connection to an OCSP responder.

#### Disadvantages:
**Optionality:** Standard stapling is optional; if an attacker strips the stapled response, browsers typically default to a "soft-fail" behavior, meaning they ignore the missing status and proceed with the connection.
**Cache Duration:** The freshness depends on the server's cache refresh interval.

### OCSP Must Staple
To address the soft-fail weakness of standard stapling, the X.509 certificate extension OCSP Must Staple was introduced. This extension is embedded directly within the server's certificate that signals to the browser that a stapled OCSP response is mandatory.

#### Advantages:
**Security:** It effectively eliminates the "soft-fail" vulnerability by turning it into a "hard-fail"; the browser must reject the certificate if the stapled response is missing or invalid.

#### Disadvantages:
**Availability Risk:** If the CA's OCSP responder is down and the server cannot fetch a fresh response, the website becomes completely inaccessible to users until a new response is available.

---

## 5. SSH Authentication

"What are the available types of peer authentication in SSH? Describe which techniques they use and discuss their specific weaknesses."

SSH separates authentication into two distinct phases to ensure that client credentials are only transmitted after a secure, encrypted channel has been established.

1. **Server Authentication**: This is the first step in an SSH connection, ensuring the client is connecting to the correct server.
It uses an asymmetric challenge-response mechanism where the server proves its identity by performing a digital signature on the Key Exchange Hash. The client verifies this signature against its local database of trusted public keys.

   - **Weaknesses:**
      - **TOFU:** If the server's key is missing from the client's known_hosts file, the user is prompted to accept the key blindly based on a fingerprint. This relies entirely on human verification.
      - **MITM:** Since SSH traditionally lacks a hierarchical PKI, it is vulnerable to Man-In-The-Middle attacks if a user ignores warnings and accepts a malicious server's public key.

2. **Client Authentication**: This step occurs only after the encrypted channel is established.

   - **Methods:**
      1. **Username and Password:**
         The client sends the plaintext credentials to the server over the encrypted channel.
         - **Weaknesses:**
            - Despite encryption, it remains vulnerable to on-line password enumeration and brute-force attacks.

      2. **Public Key Authentication:**
         An asymmetric challenge-response is used. The client proves possession of a private key without ever sending it over the network. The server checks the client's signature against the ~/.ssh/authorized_keys file.
         - **Weaknesses:**
            - The security relies entirely on the client's platform integrity. Malware can inject malicious DLLs to steal credentials or private keys.

      3. **Other Methods:**
         - Methods like X.509 certificates or GSS-API.

---

## 6. Attacks against SSH

"Explain vulnerabilities such as brute force, MITM via TOFU, and specialized tools like Gyrfalcon."

1. **MITM via TOFU:**
   SSH relies on direct trust in public keys rather than a centralized PKI, so the client stores trusted keys in `~/.ssh/known_hosts`.
   If a key is not present, like in the first use, it is offered to the user. Security relies entirely on the user manually verifying the fingerprint. An attacker can perform a MITM attack by presenting a fake key. Since users often ignore warnings and blindly accept the new server key, they allow the attacker to decrypt and modify the session.

2. **Brute Force Attacks:**
   These attacks exploit insecure authentication rather than protocol flaws. Attackers use automated scripts to perform on-line password enumeration using dictionaries of common passwords against standard accounts.

3. **Specialized Malware:**
   These tools bypass SSH encryption by attacking the client/server platform directly.
   - **Gyrfalcon:** Targets OpenSSH on enterprise Linux. It pre-loads a malicious DLL to intercept plaintext traffic before encryption or after decryption.
   - **BothanSpy:** Targets the Xshell client on Windows. It injects a malicious DLL to steal credentials and exfiltrates them via a covert channel to a C&C server.

---

## 7. Attacks against OCSP

"Explain which are the possible attacks on OCSP protocol."

The OCSP protcol, introduces several security and operational vulnerabilities:

1. **Replay Attack:**
   An attacker captures a valid, signed OCSP response indicating a certificate is good and replays it to the client even after the certificate has been revoked.
   The client accepts the old response because the signature is mathematically valid, allowing a revoked certificate to be trusted. This attack can be avoided if the client inserts a Nonce in the request. The responder is required to include this exact Nonce in the signed response, proving freshness and binding the response to that specific request.

2. **Denial of Service:**
   The OCSP protocol is vulnerable to flooding attacks because generating a response requires the server to perform a digital signature, which is a computationally slow and expensive operation.
   The attacker floods the responder with many requests. If the server signs every response in real-time, it becomes overloaded and unavailable.
   To avoid real-time signing load, responders often pre-compute responses for all issued certificates periodically. Since pre-computation is incompatible with the Nonce, the responder must choose between being protected against DoS with pre-computation or being protected against Replay attacks using nonces.

3. **Privacy and Implementation Attacks:**
   Every OCSP request contain the serial number of the certificate being checked. This leaks the user's entire navigation history to the CA and leads to privacy issue.
   Most browsers implement a soft-fail policy for OCSP. if an attacker can block the network connection to the OCSP responder with a MITM attack, the browser will fail open and accept the certificate as valid rather than denying access to the site. This allows an attacker to force the use of a revoked certificate simply by making the responder unreachable.

---

## 8. Certificate Validation

"Certificate validation in a hierarchical PKI (include: Authority Information Access, Certificate Authority, Issuer Access, CRL distribution point)."

Validation in a hierarchical PKI requires constructing and verifying a certification path from the End Entity certificate up to a trusted Trust Anchor which is typically,a self-signed Root CA certificate.
For each certificate in the chain the verifier must perform three checks:
1. Signature verification: checking the digital signature using the public key of the issuer
2. Temporal Validity - Ensuring the current time falls within the notBefore and notAfter period
3. Revocation Status - Verifying that the certificate has not been revoked by the CA.

To facilitate these operations, X.509v3 defines several key extension:
1. Authority Information Access: This extension indicates how to access information and services of the CA that issued the certificate. It defines two specific accessMethod types:
   - **calssuers**: used to fetch the issuer's certificate to aid in path construction
   - **ocsp**: used to locate the OCSP responder for real time validity checks.
2. Subject Information Access: is  also referred to as CA Information Access when present in CA certificates, this indicates how to access services provided by the subject of the certificate. it is different from AIA because it points to services the current certificate holder offers, rather than services offered by its issuer.
3. CRL Distribution Point: identifies the URI where the verifier can download the CRL. This is critical for scalability as it allows partitioning the CRL into smaller groups, preventing the need to download a single monolithic list of all revoked certificates.

---

## 9. Certificate Assessment

"If you receive a digitally signed document with its certificate chain, how can you assess the certificate status and validity without any external/a-priori knowledge (having only the PKC itself)?"

To assess the status and validity of a digitally signed document without a-priori configuration, the Relying Party must perform dynamic discovery by exploiting the X.509v3 extensions embedded in the certificate.


Initially, the RP checks the Validity field. Since the verification concerns a document, validity must be established relative to the signing time rather than the current verification time; this requires the presence of a Time-Stamp Token issued by a Time-Stamping Authority, which cryptographically proves the data existed before a specific timestamp, allowing the RP to verify that the certificate was valid at the moment of signing even if it is currently expired or revoked. 
To check the revocation status, the RP discovers where to check for revocation using two specific extensions: 
The CRL Distribuition Point that provides the URI to download the Certificate Revocation List
Authority Information Access, using the ocsp access method to locate the OCSP responder for a real time verification.
If the provided certificate chain is incomplete, the RP uses the AIA extension of the current certificate. By using calssuers access method, the RP can dynamically fetch the certificate of the issuing CA
The process of fetching issuers continues upward unitl a Trust Anchor is reached. Crucially, while intermediate certificate can be discovered dynamically, the root CA must already be present in the RP's local trust store. A root CA certificate cannot be downloaded and trusted blindly via AIA; it must be a-priori known to serve as the ultimate origin of trust for the entire chain.

---

## 10. X.509 Extension

"Explain the SubjectAltName (SAN) extension: what is it, what is its purpose, and make an example. Furthermore, explain Key Usage (KU) and Extended Key Usage (EKU): why do we use them, why do we favor EKU over KU? Provide 2 examples of values for both."

The Subject Alternative Name is an X.509v3 standard public extension that allows binding the public key to various formalism beyond the traditional X.500 Distinguished Name; notably, this extension must be marked as critical if the standard subject-name field is left empty. An example is a web server certificate using dNSName to list valid domains.

Regarding key constraints, Key Usage restricts the specific cryptographic operations the public key can perform, such as digitalSignature and keyEncipherment. However, defining usage solely by cryptographic operations is considered too wide and generic; for instance, digital signature could validly apply to signing a legal contract. Therefore, Extended Key Usage is favoured because it restricts the key to specific application domains rather than just cryptographic mechanisms. For example, EKU values like serverAuth or codeSigning allow a Relying Party to reject a certificate if it is used in the wrong context, even if the cryptographic operation is technically valid.

---

## 11. Timestamping

"What is secure timestamping and how does it work? What is possible to say about when a document was created, signed, and timestamped?"

Secure timestamping is a mechanism used to provide a cryptographic proof of existence of a datum before a specific point in time, guaranteed by a Trusted Third Party called a Time-Stamping Authority. The process is defined in by RFC 3161 and involves the Time-Stamp Protocol. To preserve privacy, the client does not send the actual document byt transmits its digest to the TSA. The TSA reads the time from a highly accurate source like an atomic clock and generates a Time-Stamp Token. This token contains the received hash and the date/time, digitally signed by the TSA to ensure authenticity and prevent tampering; if the document is modified after this point, the hash will not match, invalidating the token.

Regarding the temporal status of the document:
1. **Creation:** The timestamp is not a proof of creation at that specific instant; it only proves the document existed no later than the time indicated in the TST. The data could have been created minutes or years before.
2. **Signing:** If the timestamp is applied to a digital signature, it freezes the validation context. It proves the signature was generated when the signer's certificate was still valid, allowing the signature to be verified as valid in the future even if the certificate is subsequently expired or revoked.
3. **Timestamping:** This represents the only certifiable moment in the timeline, proving that the specific bit-stream of the document was fixed and existed at that precise instant.

---

## 12. Trusted Computing Environment

"Sealing and Binding: Explain Binding and Sealing in a Trusted Computing environment(TPM). What is the difference between them? Describe the sealing operation and provide an example of a real application."

In Trusted Computing, the TPM provides cryptographic isolation for data stored outside the chip through two distinct mechanisms: Binding and Sealing.

- **Binding:** Encrypts data using a non-exportable RSA key managed by TPM. This key is part of a hierarchy that descends from the Storage Root Key. Data protected via binding is tied to a specific hardware device; it can only be decrypted by that specific TPM, but the operation is independent of the current software or platform state.
- **Sealing:** An advanced form of binding that adds Mandatory Access Control based on the platform's integrity state. Data is decryptable only if the platform matches a specific hardware and software configuration.

The Difference: Binding ensures data confidentiality tied to a specific physical machine. Sealing ensures data confidentiality tied to both the specific machine and a specific trusted state.

The Sealing Operation involves the following steps:
The system components are measured during the boot sequence using the EXTEND operation, which accumulates hashes into the Platform Configuration Registers
The TPM encrypts the data and attaches a sealing policy.This policy links the data to specific values of one or more PCRs. When an Unseal command is issued, the TPM hardware compares the current PCR values against the values required by the sealing policy. If and only if they match, the TPM releases the decryption key, otherwise the TPM refuses to release the key.

Real Application Example: Microsoft BitLocker seals the Volume Encryption Key within the TPM, targeting PCRs that represent the integrity of the BIOS, the Master Boot Record, and the boot configuration.
If an attacker installs a rootkit or modifies the boot sequence to intercept the password, the measurement of the boot components will change. Consequently, the PCR values will not match the sealed policy and the TPM will refuse to unseal the disk encryption key, preventing the compromised OS from starting.

---

## 13. Remote Attestation

"Define and explain the procedure/process of remote attestation in a trusted computing environment."

Remote Attestation is a challenge-response protocol used to provide verifiable evidence of a platform's hardware and software state to an external Verifier, establishing trust in the system's identity and integrity. The procedure begins with the Verifier sending a random Nonce to the Attester to prevent replay attacks. Upon receipt, the Attester invokes the TPM's Root of Trust for Reporting to retrieve the integrity measurements stored in the Platform Configuration Registers, which serve as the Root of Trust for Storage; these PCRs contain the accumulated digests of the boot sequence and potentially runtime measurements. The RTR generates a digital signature over the selected PCR values and the Nonce using an Attestation Identity Key. The AIA is restricted signign key generated inside the TPM to protect the platform's privacy. The resulting signed object is called a Quote.
The Attester sends the Quote along with a Stored Measurement Log to the verifier.
The Verifier validates the digital signature and checks the nonce's freshness. Finally, the verifier compares the reported measures against a database of Reference Measurements to determine if the platform is in a trustworthy state.

---

## 14. Root of Trust and Boot Processes

"Define Root of Trust: what is its role in Trusted Computing, and which kinds are implemented by a TPM? Describe the characteristics, features, and tasks of secure boot, trusted boot, and measured boot, clearly stating to which boot phases they apply and which security feature they offer."

A Root of Trust (RoT) is defined as a component that must always behave in the expected manner because its misbehavior cannot be detected at runtime; it serves as the fundamental building block for establishing trust in a platform. Within the context of Trusted Computing, the Trusted Platform Module (TPM) implements the Root of Trust for Storage (RTS), which provides shielded locations (specifically Platform Configuration Registers or PCRs) to store integrity measurements, and the Root of Trust for Reporting (RTR), which securely reports the contents of the RTS to external verifiers using digital signatures. Notably, the TPM is not the Root of Trust for Measurement (RTM); the Core RTM (CRTM) is typically the immutable first instructions executed by the CPU (e.g., in the BootROM) that initiate the chain of trust.

Regarding the boot processes, Secure Boot applies to the initial firmware and bootloader phases (up to the OS loader); it enforces a security policy where the firmware verifies the digital signature of the next component in the chain, and if verification fails, the platform is halted to prevent the execution of unauthorized code like rootkits or bootkits. Trusted Boot operates during the subsequent OS initialization phase (loading the Kernel, System Drivers, and Anti-malware); the OS verifies the signatures of these components, and if a check fails, the specific component is not loaded (though the system may continue to boot), ensuring only authorized drivers run. Finally, Measured Boot spans the entire process from the CRTM through the OS and applications; it follows a "measure-then-load" paradigm where the hash of every component is computed and stored in the TPM's PCRs via the extend operation before execution. Unlike Secure Boot, Measured Boot does not stop execution; instead, it provides a tamper-evident log (chain of trust) that allows an external entity to audit the platform's state via Remote Attestation.

---

## 15. Quantum Key Distribution

"Describe the BB84 (or PK84) protocol. Discuss its strong and weak points (strengths and weaknesses), not only in theory but also with respect to its practical applications."

The BB84 protocol establishes a shared symmetric key by transmitting quantum bits (qubits) over a quantum channel (typically optical fiber), utilizing photon polarization states as the encoding mechanism. Alice sends random bits encoded in random bases, choosing between rectilinear (vertical/horizontal) and diagonal polarization; Bob measures incoming photons by independently selecting random bases. Subsequently, during the "key sifting" phase performed over a classical authenticated channel, Bob reveals his basis choices and Alice confirms which matches occurred, allowing them to discard bits where bases differed,. The protocol concludes with error correction to handle transmission noise and privacy amplification (hashing) to eliminate partial information leaked to an adversary,.

Strengths and Weaknesses Theoretically, the protocol offers unconditional security based on the laws of physics (specifically the No-Cloning Theorem and the observer effect); any eavesdropping attempt (Eve) requires measurement, which inevitably alters the quantum state and introduces detectable errors (QBER),,. However, practical application faces severe limitations. First, QKD is not a standalone solution as it strictly requires a pre-existing authenticated classical channel to prevent Man-in-the-Middle attacks during sifting,. Second, physical constraints limit the distance to approximately 100 km and throughput to 1 Mbps because quantum signals cannot be amplified; extending range requires "trusted nodes", which forces hop-by-hop security rather than end-to-end encryption,. Finally, hardware imperfections in photon sources expose the system to the Photon Number Splitting (PNS) attack, where Eve splits multi-photon pulses to steal information undetected, a vulnerability that necessitates the use of the Decoy State protocol mitigation,.

## 16. Signatures Format

Describe the formats of documents’ digital signature: enveloping,
enveloped, and detached signatures. Which one is implemented/used in PDF?

Electronic signatures relate to the signed document structure in three fundamental formats: enveloping, enveloped, and detached. In the enveloping format, the digital signature effectively functions as a container that encapsulates the original document content; the data is located inside the signature object (e.g., PKCS#7), requiring extraction to be read,. Conversely, the enveloped format embeds the digital signature within the document file structure itself; the file format must support a specific "hole" or placeholder to store the cryptographic blob, allowing the document to remain readable by standard applications while carrying its own authentication (e.g., PDF or XML-DSig),. Finally, the detached format maintains the document and the signature as separate entities (files); while this preserves the original file without modification, it introduces the complexity of maintaining the link between the data and its signature to ensure verification,.

PDF Implementation: The PDF standard implements the enveloped signature format to ensure the file remains a valid, readable PDF. The document is treated as a byte stream where a specific dictionary reserves space for the signature; the /ByteRange parameter explicitly identifies the two byte intervals (the part before and the part after the reserved "hole") that constitute the signed content,. The hash is computed over these disjoint ranges and encrypted with the signer's private key. Technically, the resulting cryptographic value inserted into the reserved space is encoded as a PKCS#7 detached signature blob (typically in hex encoding, padded with zeros), creating a hybrid where a detached standard is used inside an enveloped file format,. To support multiple signatures (workflows) without invalidating previous ones, PDF utilizes incremental updates, where subsequent modifications and signatures are appended to the end of the file rather than modifying the original byte stream,.

---

## 17. SAML and eIDAS

"Draw/Explain the eIDAS infrastructure and its actors. Where is SAML used in it and what are its properties (including SAML assertions)? Discuss the Google Apps SSO scheme (Google SAML) as a comparative example."

The eIDAS infrastructure facilitates cross-border electronic identification by connecting a Service Provider (SP) in a Receiving Member State (MS) to a user from a Sending MS. The architecture relies on two critical nodes: the eIDAS Connector located in the Receiving MS, which requests authentication, and the eIDAS Service in the Sending MS, which provides the identity assertions. The eIDAS Service acts as a bridge to national Identity Providers (IdPs) and can be implemented as a Proxy Service (a centralized gateway, e.g., Italy) or a Middleware Service (decentralized software running in the Receiving MS, e.g., Germany),,.

SAML is the mandatory interoperability protocol used for the cross-border exchange between the Connector and the Service. The SAML Request contains no personal data but must be digitally signed to authenticate the requesting MS, transmitted via HTTP Redirect or POST,. The SAML Response carries the user's identity and requires higher security: it must be digitally signed and contain an EncryptedAssertion (protecting personal data via AES-GCM and key transport via RSA-OAEP or ECDH-ES) which includes the AuthnStatement and the AttributeStatement (the Minimum Data Set), transmitted via POST binding to the Connector's Assertion Consumer Service (ACS),.

Comparative Example: Google Apps SSO In contrast, the Google Apps SSO scheme utilizes a standard SAML 2.0 Web Browser SSO profile where the Partner company acts as the IdP and Google acts as the SP. Unlike the multi-hop eIDAS architecture, Google's model is a direct relationship: Google generates a SAML request containing the ACS URL and the specific service URL (in opaque mode) and redirects the browser to the Partner's SSO URL; after authentication, the Partner generates a digitally signed SAML response (without the mandatory encryption requirements of eIDAS) and returns it to Google's ACS for verification,,.

---

## 18. PEP and PDP

"Explain what are PEP (Policy Enforcement Point) and PDP (Policy Decision Point). Make an example of their real implementations. Describe which SAML messages and in which way could be used to support their operations."

The Policy Enforcement Point (PEP) serves as the gateway protecting a specific resource, effectively acting as the "guard at the door" that intercepts access requests and enforces the final admission decision (permit or deny), whereas the Policy Decision Point (PDP) is the centralized entity responsible for evaluating these requests against access policies, subject attributes, and environmental context to render a judgment. In real-world implementations, a PEP is typically embedded within components such as a web server, firewall, or XML gateway, which block traffic until authorization is granted, while the PDP is a centralized server (often implementing XACML logic) that allows for delegated authorization across an organization. To support these operations, SAML defines a producer-consumer model where the PEP acts as the system entity requester by sending a SAML Authorization Decision Query to the PDP, explicitly asking for a ruling on a specific subject's access rights regarding a resource. The PDP acts as the asserting party and responds with a SAML Authorization Decision Assertion; this assertion contains an <AuthorizationStatement> that explicitly declares the decision (e.g., Decision="Permit" or Decision="Deny") based on the evidence provided, which the PEP then consumes to enforce the access control decision.

---

## 19. Delegated Authentication Model

"Describe the Delegated Authentication model. Outline two possible scenarios and the related problems."

In distributed systems, Relying Parties (RP) (application servers) delegate the task of user verification to a trusted third party, the Authentication Server (AS). Instead of managing local databases, the RP redirects the client to the AS, which executes the authentication protocol (e.g., password, challenge-response). Upon success, the AS generates an authentication ticket (or assertion) certifying the user's identity, which is then transmitted to the RP to authorize access,.

Transmission Scenarios

1. **Push Ticket:** The AS sends the ticket directly to the RP. This requires the RP to have an active listening service to receive the connection from the AS.
2. **Indirect Push (or Push Reference + Pull):** The AS sends the ticket (or a reference/artifact) to the Client, which forwards it to the RP. If a reference is used, the RP subsequently "pulls" the actual ticket from the AS. This method is often preferred when the RP is behind a firewall that blocks incoming connections from the AS,.

Related Problems

- **Binding:** Ensuring the ticket is bound to the specific client node presenting it, preventing theft and use by others,.
- **Ticket Integrity & Authenticity:** Preventing manipulation (forging data) or creation of fake tickets; this requires the ticket to be digitally signed by the AS,.
- **Replay and Reuse:** Attackers may intercept a valid ticket to use it later (replay) or on a different server (reuse); mitigation requires timestamps, short validity periods, and audience restrictions,.
- **Network Constraints:** The "Push" model faces issues if the RP has incoming firewalls blocking the AS; the "Indirect" model exposes the ticket to potential sniffing at the client side, requiring encryption for privacy,.
