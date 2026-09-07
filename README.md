# VeriTrace

> **Verify the file. Trace the history. Trust the evidence.**

Cryptographic chain-of-custody for digital files — combining SHA-256 hashing, Ed25519 digital signatures, and a hash-linked custody ledger to prove not just *what* a file is, but *who handled it* and *what happened to it*.

---

## What it does

Traditional file verification answers: *"Is this file the same as the one I have?"*

VeriTrace answers: *"Who handled this file, what happened to it, and can the entire history be cryptographically verified?"*

Every action performed on a file — creation, modification, transfer — produces a signed record in a tamper-evident chain:

```
CREATE → MODIFY → TRANSFER → MODIFY → VERIFY
```

If a file is altered outside the recorded workflow, its SHA-256 hash diverges from the latest trusted record and VeriTrace flags it immediately.

---

## Setup

### Prerequisites

- Python 3.8+

### 1. Clone

```bash
git clone https://github.com/nihan-98716/VeriTrace.git
cd VeriTrace
```

### 2. Create a virtual environment

```bash
# Linux / macOS
python -m venv venv && source venv/bin/activate

# Windows
python -m venv venv && venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r backend/requirements.txt
```

### 4. Start the server

```bash
cd backend
python app.py
```

Flask API runs at `http://localhost:5000`. Open `frontend/index.html` in your browser to use the interface.

---

## How it works

### Registration

When a user registers, VeriTrace generates an **Ed25519 key pair** and stores the public key in the registry. Every subsequent action they take is signed with their private key.

### File upload (CREATE)

```
File → SHA-256 hash → CREATE record → Ed25519 signature → Ledger
```

The initial record establishes the file's cryptographic identity.

### Modify / Transfer

Each action appends a new record to the chain. Every record stores:

| Field                   | Purpose                                    |
|-------------------------|--------------------------------------------|
| File ID                 | Identifies the tracked file                |
| Current file hash       | SHA-256 of the file at this point in time  |
| Previous record hash    | Links this record to the one before it     |
| Action type             | `CREATE`, `MODIFY`, or `TRANSFER`          |
| Actor ID                | Who performed the action                   |
| Timestamp               | When it happened                           |
| Declared transformation | What was done                              |
| Metadata                | Any additional context                     |
| Digital signature       | Cryptographic proof of record authenticity |

Records are linked like this:

```
┌──────────┐
│ Record 1 │
└────┬─────┘
     │ prev_hash
     ▼
┌──────────┐
│ Record 2 │
└────┬─────┘
     │ prev_hash
     ▼
┌──────────┐
│ Record 3 │
└──────────┘
```

Altering any record in the chain breaks the link and is immediately detectable.

### Verification

VeriTrace runs six checks during verification:

1. Hash the supplied file
2. Retrieve the custody chain
3. Verify record-to-record links
4. Verify Ed25519 signatures on each record
5. Confirm all actors are registered
6. Compare the current file hash against the latest trusted record

**Possible verdicts:**

| Verdict              | Meaning                                                    |
|----------------------|------------------------------------------------------------|
| `VERIFIED`           | File and custody history are cryptographically consistent  |
| `TAMPERED`           | File or custody evidence does not match the trusted record |
| `UNKNOWN PROVENANCE` | Sufficient trusted provenance cannot be established        |

---

## API reference

| Endpoint                    | Method | Description                      |
|-----------------------------|--------|----------------------------------|
| `/api/users/register`       | POST   | Register a custodian             |
| `/api/users`                | GET    | List registered users            |
| `/api/files/upload`         | POST   | Create a new file record         |
| `/api/files`                | GET    | List tracked files               |
| `/api/files/<id>/action`    | POST   | Add a `MODIFY` or `TRANSFER` action |
| `/api/files/<id>/verify`    | POST   | Cryptographically verify a file  |
| `/api/files/<id>/history`   | GET    | Retrieve custody history         |
| `/api/files/<id>/ela`       | POST   | Generate Error Level Analysis    |

---

## Image forensics (ELA)

For supported image formats, VeriTrace provides **Error Level Analysis** as a supplementary visual aid.

```
Input image → JPEG re-save → Pixel difference → Brightness amplification → ELA output
```

ELA highlights regions of an image that may have been edited. It is a heuristic tool — useful for investigation, but not a substitute for the cryptographic verification verdict.

---

## Project structure

```
VeriTrace/
├── backend/
│   ├── app.py             # Flask REST API and routes
│   ├── crypto_engine.py   # SHA-256 hashing, Ed25519 signing, chain verification
│   ├── db.py              # SQLite init and connection handling
│   ├── ela.py             # Error Level Analysis
│   ├── requirements.txt
│   └── uploads/
├── frontend/
│   ├── index.html
│   ├── style.css
│   └── app.js
├── demo_assets/
│   ├── original_photo.jpg
│   └── tampered_photo.jpg
├── docs/
│   ├── architecture.md
|   ├── 
|   ├──
|   └──
└── README.md
```

---

## Tech stack

| Layer           | Technology               |
|-----------------|--------------------------|
| Backend         | Python, Flask            |
| Cryptography    | `cryptography`, Ed25519  |
| Hashing         | SHA-256                  |
| Database        | SQLite                   |
| Frontend        | HTML, CSS, JavaScript    |
| Image analysis  | Pillow, NumPy            |
| File storage    | UUID-based naming        |

---

## Limitations

VeriTrace is a research prototype demonstrating the core cryptographic provenance model. Current limitations:

- Private keys are held in application memory (not in a key management service)
- SQLite database is local, not distributed
- File storage is local to the server
- No production-grade authentication or access control
- ELA is heuristic — not definitive proof of manipulation

Production deployment would require hardened key management, encrypted storage, distributed infrastructure, robust authentication, and audit logging.

---

## Potential applications

- Digital forensics and legal evidence management
- News and media verification workflows
- Academic and research records
- Document provenance tracking
- Incident investigation
- Secure organizational file handoffs
