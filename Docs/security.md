### Security — File Integrity & Authenticity

For the security component of the MVP, we will use **SHA-256 hashing combined with RSA digital signatures** to verify both the **integrity and authenticity** of files.

#### 1. Generate the SHA-256 Hash

When a file is uploaded or stored, we first calculate its SHA-256 hash.

```text
File → SHA-256 → Hash
```

The hash acts as a digital fingerprint of the file. Even a small change to the file will produce a different hash.

#### 2. Create an RSA Digital Signature

The generated SHA-256 hash is then digitally signed using an **RSA private key**.

```text
SHA-256 Hash
      │
      ▼
RSA Private Key
      │
      ▼
Digital Signature
```

The signature is stored along with the file and its associated metadata.

#### 3. Verify the File

When the file needs to be verified:

* The current file is hashed again using SHA-256.
* The RSA signature is verified using the corresponding **RSA public key**.
* The verification confirms that the signature is valid and that the file has not been altered.

```text
              Original File
                    │
                    ▼
              SHA-256 Hash
                    │
                    ▼
            RSA Private Key
                    │
                    ▼
           Digital Signature
                    │
              ┌─────┴─────┐
              │   Stored   │
              └─────┬─────┘
                    │
              Verification
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
     Current File        RSA Signature
          │                   │
          ▼                   ▼
     SHA-256 Hash        RSA Public Key
          │                   │
          └─────────┬─────────┘
                    ▼
              Verify Signature
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
       Valid ✓             Invalid ✗
    File authentic       File modified /
                         signature invalid
```

### What Each Component Provides

| Component             | Purpose                                          |
| --------------------- | ------------------------------------------------ |
| **SHA-256**           | Detects whether the file's contents have changed |
| **RSA Private Key**   | Creates the digital signature                    |
| **RSA Public Key**    | Verifies the digital signature                   |
| **Digital Signature** | Provides integrity and authenticity verification |

### Verification Result

If the SHA-256 hash of the current file matches the hash that was originally signed, **and the RSA signature successfully verifies with the public key**, the file can be considered unchanged and signed by the expected key holder.

If the file is modified, the newly calculated hash will differ, causing signature verification to fail.

> **In short:** SHA-256 provides the file's digital fingerprint, while RSA signing proves that the fingerprint was created by the holder of the private key and has not been altered.

**### Security Development Log — Transition from RSA to Ed25519**

After implementing the initial **SHA-256 + RSA** security mechanism, we will test the system for file integrity and authenticity.

The initial implementation successfully demonstrates that:

* SHA-256 can detect changes to file contents.
* RSA signatures can authenticate the signed hash.
* The RSA public key can verify the signature.
* Modification of the file causes verification failure.
* Modification of the stored hash or signature causes verification failure.

At this stage, the basic security requirement is satisfied using RSA.

However, as we extend VERITRACE to support **multiple custody records** such as CREATE, TRANSFER, and MODIFY, every record may require its own digital signature. This increases the importance of key size, signature size, signing speed, verification speed, and storage efficiency.

Therefore, after completing and evaluating the RSA implementation, we will investigate modern digital signature algorithms.

**Next step: replace RSA with Ed25519.**

The security flow will evolve from:

```text
File
  ↓
SHA-256
  ↓
Hash
  ↓
RSA Private Key
  ↓
Digital Signature
```

to:

```text
File
  ↓
SHA-256
  ↓
Hash
  ↓
Ed25519 Private Key
  ↓
Digital Signature
```

The reason for this change is not that RSA is insecure. **RSA is our initial working implementation.** We are introducing Ed25519 because it provides a more compact and efficient signature mechanism that is better suited to VERITRACE's future design involving many signed custody records.

SHA-256 will remain unchanged because it performs a different role:

```text
SHA-256  →  File Integrity
Ed25519  →  Digital Signature / Signer Authentication
```

The next development stage will therefore be:

```text
SHA-256 + RSA
       ↓
Test & Evaluate
       ↓
Identify Requirements for Repeated Records
       ↓
Research Modern Signature Schemes
       ↓
Introduce Ed25519
       ↓
SHA-256 + Ed25519
```

After the Ed25519 implementation is working correctly, we will proceed to the next security enhancement: **multiple signed custody records followed by cryptographic hash chaining.**
