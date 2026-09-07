# VERITRACE — System Architecture

VERITRACE is a cryptographic chain-of-custody platform that gives digital files a verifiable identity and records every custody action in a signed, hash-linked ledger.

```mermaid
flowchart LR

    %% =========================
    %% USERS
    %% =========================

    USER["👤 CUSTODIANS<br/><br/>Reporter<br/>Editor<br/>Publisher"]

    %% =========================
    %% FRONTEND
    %% =========================

    subgraph FRONTEND["🖥️ PRESENTATION LAYER"]
        UI["VERITRACE WEB APP<br/><br/>Register • Upload<br/>Custody Timeline • Verify"]
    end

    %% =========================
    %% BACKEND
    %% =========================

    subgraph BACKEND["⚙️ BACKEND — Flask REST API"]

        API["REST API<br/><br/>Register User<br/>Upload File<br/>Modify / Transfer<br/>Verify<br/>History<br/>ELA"]

        subgraph CRYPTO["🔐 CRYPTO ENGINE"]

            HASH["SHA-256<br/>File Fingerprint"]

            SIGN["Ed25519<br/>Digital Signature"]

            CHAIN["Hash-Linked<br/>Custody Chain"]

            VERIFY["Chain Replay<br/>Signature + Hash Verification"]

        end

        ELA["🖼️ ELA ANALYSIS<br/><br/>Supporting forensic signal<br/>for image manipulation"]

    end

    %% =========================
    %% STORAGE
    %% =========================

    subgraph STORAGE["💾 STORAGE"]

        DB["SQLite Ledger<br/><br/>Users<br/>Files<br/>Ledger Records"]

        VAULT["📦 File Vault<br/><br/>UUID-isolated files"]

    end

    %% =========================
    %% VERDICT
    %% =========================

    RESULT{"🔎 CRYPTOGRAPHIC<br/>VERDICT"}

    VERIFIED["🟢 VERIFIED<br/><br/>Unbroken custody chain"]

    TAMPERED["🔴 TAMPERED<br/><br/>Broken hop + actor identified"]

    UNKNOWN["⚪ UNKNOWN PROVENANCE<br/><br/>No registered history"]

    %% =========================
    %% MAIN FLOW
    %% =========================

    USER -->|"Register / Upload /<br/>Modify / Transfer / Verify"| UI

    UI --> API

    API --> HASH
    API --> SIGN
    API --> CHAIN
    API --> VERIFY
    API --> ELA

    API --> DB
    API --> VAULT

    %% =========================
    %% CREATION
    %% =========================

    HASH -->|"File content hash"| SIGN
    SIGN -->|"Signed record"| CHAIN
    CHAIN -->|"Persist custody record"| DB

    %% =========================
    %% CUSTODY
    %% =========================

    DB -->|"Previous record hash<br/>+ actor public key"| CHAIN

    CHAIN -->|"CREATE → TRANSFER → MODIFY → ..."| DB

    %% =========================
    %% VERIFICATION
    %% =========================

    VERIFY --> RESULT

    DB -->|"Ledger history"| VERIFY
    HASH -->|"Current file hash"| VERIFY

    RESULT -->|"All hashes + signatures valid"| VERIFIED
    RESULT -->|"Hash/signature mismatch"| TAMPERED
    RESULT -->|"No custody history"| UNKNOWN

    %% =========================
    %% ELA
    %% =========================

    ELA -->|"Heatmap"| UI

    VERIFIED --> UI
    TAMPERED --> UI
    UNKNOWN --> UI
```

## 🔐 How VERITRACE Works

1. **Register** — A custodian receives an Ed25519 cryptographic identity.
2. **Create** — The uploaded file is SHA-256 hashed and recorded in a signed `CREATE` record.
3. **Track** — Every `TRANSFER` or `MODIFY` action creates another signed record linked to the previous record using `prev_record_hash`.
4. **Verify** — The current file is hashed again and the entire custody chain is replayed. Every signature and hash link is validated.
5. **Verdict** — VERITRACE returns:
   - 🟢 **VERIFIED** — the file and custody chain are consistent.
   - 🔴 **TAMPERED** — a cryptographic inconsistency is detected and the broken hop is identified.
   - ⚪ **UNKNOWN PROVENANCE** — no registered custody history exists.
6. **ELA** — For images, Error Level Analysis provides a visual forensic signal alongside the cryptographic verdict.

### Core Principle

> **SHA-256 proves what the file is.  
> Ed25519 proves who signed it.  
> Hash chaining proves what happened to it.  
> Verification proves whether the history still holds.**

### Technology Stack

`Frontend: HTML/CSS/JS` · `Backend: Python + Flask` · `Cryptography: Ed25519 + SHA-256` · `Database: SQLite` · `Image Analysis: Pillow + NumPy` · `Storage: Local UUID File Vault`
