# VeriTrace

> **Verify the file. Trace the history. Trust the evidence.**

VeriTrace is an end-to-end cryptographic chain-of-custody and digital forensics system. It combines SHA-256 content hashing, Ed25519 / Hybrid Post-Quantum signatures, RFC 3161 external trusted timestamping, Zero-Knowledge Merkle redaction, frequency-domain forensic localization (2D-FFT & Block-DCT), and grounded semantic NLP to prove not just *what* a file is, but *who handled it, when it was certified, and exactly how it was altered*.

---

## Key Capabilities

### 1. Cryptographic Chain-of-Custody (Ledger)
- **Immutable Forward Linkage**: Every action (`CREATE`, `TRANSFER`, `MODIFY`, `REDACT`) produces a hash-linked block referencing `prev_record_hash`.
- **Hybrid Digital Signatures**: Supports classical Ed25519 as well as Hybrid Post-Quantum (PQC) digital signatures (ML-DSA / Dilithium compatible) for quantum-resistant verification.
- **Strict Transfer Invariance**: A `TRANSFER` action strictly forbids file byte alterations; content modifications must be formally declared via `MODIFY` or `REDACT`.
- **Persistent Key Infrastructure**: Signer keypairs are serialized via PKCS#8 PEM format and stored persistently in SQLite so identities survive server restarts.

### 2. RFC 3161 External Trusted Timestamping (TSA)
- **Third-Party Notarization**: Automatically generates and submits SHA-256 digest timestamp requests to an RFC 3161 compliant Time Stamping Authority (FreeTSA).
- **Cryptographic Time Tokens**: Extracts, stores, and cryptographically verifies ASN.1 DER Timestamp Tokens (`.tsr`), policy OIDs, token serial numbers, and certificate chains.
- **Dual Timezones**: Surfaces legally verifiable timestamps formatted in both UTC and Indian Standard Time (IST).

### 3. Zero-Knowledge Verifiable Redaction (ZK-Redaction)
- **Merkle Tree Selective Disclosure**: Redact sensitive lines or sections from text documents while cryptographically verifying that unredacted content perfectly preserves the certified genesis Merkle root.
- **Authentic Redaction Verification**: The verification engine recognizes authentic redaction proofs (`VERIFIED_REDACTED`), distinguishing authorized privacy redaction from malicious tampering.

### 4. Frequency Domain & Spatial Forensics
- **Error Level Analysis (ELA)**: Re-saves images across fixed compression matrices to highlight regional compression inconsistencies.
- **2D-FFT Power Spectrum**: Fast Fourier Transform spatial frequency decomposition analyzing radial residuals, conjugate symmetry, and high-frequency harmonics to detect synthetic generative AI lattice grids.
- **8×8 Block-DCT Splicing Localization**: Computes Discrete Cosine Transform block differential matrices against the genesis benchmark to localize foreign spliced regions down to exact pixel coordinates `(x, y, w, h)`.

### 5. Grounded Semantic NLP Assessment
- **Deterministic Document Analysis**: Strictly extracts line-by-line diffs, numerical entity shifts, polarity inversions, antonym flips, and clause mutations.
- **Risk Severity Categorization**: Automatically scores document tampering into four discrete risk levels: `CRITICAL`, `SUBSTANTIVE`, `MODERATE`, or `BENIGN`, with exact side-by-side quotes.

### 6. Modality Isolation & Decoupled Verification
- **Strict Format Routing**: Image forensics (ELA, FFT, Block-DCT) are strictly reserved for image files; text files strictly route to Merkle ZK and NLP analysis.
- **Decoupled Verification Pipeline**:
  - **Chain Verification**: Evaluates the certified Genesis file against the ledger to pinpoint historical rollbacks, stale versions, or unauthorized modification hops.
  - **Forensics Pipeline**: Evaluates the active modified/tampered asset against the Genesis baseline to localize spatial, compression, and frequency deviations.

---

## Project Structure

```
VeriTrace/
├── backend/
│   ├── app.py                   # Flask REST API endpoints & route handlers
│   ├── db.py                    # SQLite schema, persistent key store & connections
│   ├── requirements.txt         # Python dependencies
│   ├── uploads/                 # Storage for genesis, latest, and candidate files
│   └── veritrace.db             # SQLite database (ledger, files, users)
├── frontend/
│   ├── index.html               # Single-page UI (Onboarding, Register, Timeline, Verify)
│   ├── veritrace.css            # Dark forensic dashboard styles
│   └── app.js                   # Client controller, API client & dynamic renderers
├── security/
│   ├── crypto_engine.py         # SHA-256, Ed25519, Hybrid PQC & verify_chain logic
│   ├── ela.py                   # Error Level Analysis (ELA) heatmap generation
│   ├── frequency_forensics.py   # 2D-FFT power spectrum & 8x8 Block-DCT splicing
│   ├── semantic_assessor.py     # Grounded NLP entity & polarity tamper assessor
│   ├── zk_redaction.py          # Merkle tree zero-knowledge redaction engine
│   ├── tsa_client.py            # RFC 3161 HTTP client, ASN.1 parsing & verification
│   └── document_forensics.py    # Segment-level document hashing & comparison
├── testcont/                    # Demonstration assets (original/tampered images & text)
├── docs/                        # Architecture, DB schema, and API documentation
└── README.md                    # Project documentation
```

---

## Setup & Installation

### Prerequisites
- Python 3.8+
- Modern web browser (Chrome, Firefox, Edge, Safari)

### 1. Clone the Repository
```bash
git clone https://github.com/nihan-98716/VeriTrace.git
cd VeriTrace
```

### 2. Set Up Virtual Environment
```bash
# Linux / macOS
python -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 4. Run the Application

Start the Flask backend server:
```bash
python backend/app.py
```
The backend API starts at `http://127.0.0.1:5000`.

Start a static web server for the frontend (in a separate terminal):
```bash
cd frontend
python -m http.server 3000
```
Open `http://localhost:3000` in your web browser.

---

## How It Works

### Step 1: Custodian Registration
When an actor registers (e.g. `Alice`, `Bob`), VeriTrace generates a certified keypair (Ed25519 or Hybrid PQC). The public key is recorded in the registry, and the private key is serialized via PKCS#8 PEM into the local database.

### Step 2: File Ingestion (`CREATE`)
Uploading a file computes its SHA-256 content hash, packages it with actor metadata, requests an external RFC 3161 certified timestamp token, signs the record, and appends it to the immutable SQLite ledger.

### Step 3: Chain-of-Custody (`TRANSFER` / `MODIFY` / `REDACT`)
- **TRANSFER**: Hands over custody to another registered actor while asserting identical file hash.
- **MODIFY**: Records an intentional content update, saving the new version and linking its new hash to the preceding block.
- **REDACT**: Computes Merkle leaf hashes for all text lines, blacks out selected lines, and generates a zero-knowledge membership proof referencing the genesis Merkle root.

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ Hop 1: CREATE   │       │ Hop 2: TRANSFER │       │ Hop 3: MODIFY   │
│ Actor: Alice    │──────▶│ Actor: Bob      │──────▶│ Actor: Alice    │
│ Hash: 1f814cc3… │       │ Hash: 1f814cc3… │       │ Hash: e59bfcc5… │
│ TSA: Certified  │       │ TSA: Certified  │       │ TSA: Certified  │
└─────────────────┘       └─────────────────┘       └─────────────────┘
```

### Step 4: Verification & Forensic Inspection
When verifying an asset:
1. **Chain Verification**: Replays every digital signature in sequence, validates RFC 3161 timestamps, checks key revocation dates, and verifies hash continuity.
2. **Tamper Diagnosis**: If content diverges, VeriTrace identifies whether it is an `EXTERNAL_MODIFICATION` or a `HISTORICAL_ROLLBACK` and pinpoints the exact custodian and hop where divergence occurred.
3. **Forensic Overlays**:
   - **Images**: Displays ELA compression artifacts and 8×8 Block-DCT differential splicing heatmaps with coordinate localization.
   - **Text**: Displays ZK Merkle proof statuses and NLP risk assessments highlighting modified entities, dates, dollar amounts, or inverted clauses.

---

## API Reference

| Endpoint | Method | Description |
| :--- | :--- | :--- |
| `/api/users/register` | `POST` | Registers a new custodian and returns public key metadata |
| `/api/users` | `GET` | Returns list of all active registered custodians |
| `/api/files/upload` | `POST` | Uploads and registers a new file (`CREATE` record) |
| `/api/files` | `GET` | Lists all registered files with status & latest filename indicators |
| `/api/files/<id>/action` | `POST` | Appends a `TRANSFER` or `MODIFY` custody hop |
| `/api/files/<id>/redact` | `POST` | Executes ZK Merkle redaction on text files |
| `/api/files/<id>/verify` | `POST` | Verifies cryptographic chain-of-custody and provenance |
| `/api/files/<id>/history` | `GET` | Returns chronological custody timeline with TSA audit tokens |
| `/api/files/<id>/ela` | `POST` | Returns Error Level Analysis (ELA) heatmap image |
| `/api/files/<id>/frequency_analysis` | `POST` | Computes 2D-FFT and Block-DCT differential splicing localization |
| `/api/reset` | `POST` | Clears all records, users, and uploaded files for clean-state testing |

---

## Verification Verdicts

| Status | Meaning |
| :--- | :--- |
| `VERIFIED` | Complete cryptographic integrity. Every signature, timestamp, and hash link is unbroken. |
| `VERIFIED_REDACTED` | Valid Zero-Knowledge Redaction. Unredacted lines match genesis Merkle root; redacted portions are certified authentic. |
| `TAMPERED` | Chain broken. Pinpoints exact failure reason: signature mismatch, unauthorized transfer edit, historical rollback, or external alteration. |
| `UNKNOWN_PROVENANCE` | File ID not registered or custody records missing. |

---

## Tech Stack

- **Backend**: Python 3, Flask, SQLite3
- **Cryptography**: `cryptography` (Ed25519, PKCS#8 PEM), hashlib (SHA-256), Hybrid PQC simulation
- **Timestamping**: RFC 3161 ASN.1 DER token parser & FreeTSA client
- **Forensics**: NumPy, SciPy (2D-FFT, Block-DCT), Pillow (ELA)
- **Frontend**: Vanilla JavaScript (ES6+), Modern Semantic HTML5, Custom Forensic CSS Design System
- **Testing**: End-to-end integration test suites across multi-hop custody lifecycles
