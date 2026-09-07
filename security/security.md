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
