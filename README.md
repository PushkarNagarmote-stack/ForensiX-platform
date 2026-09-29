# ForensiX

**Secure media sanitization and raw-sector file recovery, with audit certificates and an AI forensic assistant.**

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)
![Status](https://img.shields.io/badge/Status-Hackathon%20Prototype-orange)

Built for **Smart India Hackathon 2026, Problem Statement SIH26149**.

[Live Platform](https://forensi-x-platform.vercel.app/) · [Forensic Studio](https://forensi-x-platform.vercel.app/studio.html) · [API Docs (Swagger)](https://forensix-platform.onrender.com/docs) · [GitHub](https://github.com/PushkarNagarmote-stack/ForensiX-platform)

---

## Overview

ForensiX combines two halves of the data lifecycle in one platform:

1. **Recover:** carve deleted or unallocated files straight from raw disk sectors, without relying on filesystem metadata.
2. **Sanitize and prove it:** overwrite a disk using recognized sanitization methods, verify the result, and issue a PDF audit certificate with before/after hashes and an entropy reading.

After a wipe, the same carver is run again to show that nothing can be recovered. That recover → wipe → re-scan loop is the core of the demo.

> **Important:** this is a prototype that operates on **virtual disk images (`.img`, `.raw`, `.bin`) stored inside the project's `data/disks/` folder**. It does not touch physical drives, and the API refuses any path outside that folder. The SSD Secure Erase mode is a simulation. See [Limitations](#limitations).

---

## Features

### File carving and recovery
- Scans raw sectors for file headers and footers, independent of FAT, NTFS or EXT4 tables.
- Supported types: **JPEG, PNG, PDF, ZIP** (including Office OpenXML), plus plaintext credential-style blocks.
- Computes a **SHA-256** hash for every recovered file.
- Serves recovered files for download and provides a **hex viewer** with offsets and ASCII mapping.

### Media sanitization
| Mode | What it does |
|---|---|
| `NIST_CLEAR` | Single-pass zero overwrite, then verification (aligned with NIST SP 800-88 Rev. 1 *Clear*) |
| `NIST_PURGE` | Multi-pass overwrite (random, second pattern, zero), then verification (modeled on NIST SP 800-88 *Purge*) |
| `DOD_5220_22_M` | Three-pass legacy method: `0x00`, `0xFF`, random |
| `SSD_SECURE_ERASE` | **Simulation** of an ATA/NVMe sanitize (random overwrite followed by zeroing) |

- Records **pre-wipe and post-wipe SHA-256** hashes of the image.
- Measures **Shannon entropy** (bits per byte) of sampled sectors before and after the wipe.
- Reports elapsed time and the passes executed.

### Audit certificates
- Each wipe automatically generates a **PDF certificate** (ReportLab) containing target media details, examiner name, standard used, passes, elapsed time, hash values, entropy and verification result.
- Certificates are listed in the UI and can be downloaded.

### AI forensic assistant (Google Gemini)
- **Unknown Artifact Search:** identify unfamiliar magic bytes, hashes or file extensions, with a set of curated "mystery artifact" presets.
- **DFIR Case Assistant:** answers questions about a loaded case (timeline, anti-forensics indicators, artifacts).
- Works with a Gemini API key. **Without a key, the app falls back to a built-in simulated engine** with pre-written responses, so the rest of the platform still runs. See [Privacy note](#privacy-note-on-ai-features).

### User interface
- Landing page plus **Forensic Studio**, a single-page workspace with a glassmorphic design.
- Panels for the Deep Carver, Sanitizer, Hex Inspector, Certificate Vault and Gemini Copilot.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, FastAPI, Uvicorn, Pydantic |
| Forensics engine | Pure Python (carving, wiping, entropy, hashing) |
| Certificates | ReportLab, Pillow |
| AI | Google Gemini API via HTTPX |
| Frontend | Vanilla JavaScript, HTML5, custom CSS |
| Deployment | Render (persistent service), Vercel (serverless) |

---

## Getting started

### Prerequisites
- Python 3.10 or newer
- Git

### 1. Clone
```bash
git clone https://github.com/PushkarNagarmote-stack/ForensiX-platform.git
cd ForensiX-platform
```

### 2. Install dependencies
```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 3. (Optional) Enable live Gemini
The app does **not** read a `.env` file automatically, so set the variable in your shell before starting:

```bash
# macOS / Linux
export GEMINI_API_KEY="your_key_here"

# Windows PowerShell
$env:GEMINI_API_KEY="your_key_here"
```

You can create a key in [Google AI Studio](https://aistudio.google.com/). Optionally set `GEMINI_MODEL` to choose a model (default `gemini-2.0-flash`, with fallbacks).

### 4. Run
```bash
python server.py
```

| Page | URL |
|---|---|
| Landing page | http://127.0.0.1:8085 |
| Forensic Studio | http://127.0.0.1:8085/studio |
| Swagger docs | http://127.0.0.1:8085/docs |

Environment variables `PORT` (default `8085`) and `HOST` (default `0.0.0.0`) are supported.

### 5. Try the demo flow
1. Open the Studio and create a sample evidence disk (a 5 MB image with planted files).
2. Run the **Deep Carver** and note the recovered files and their hashes.
3. Run a wipe (for example `NIST_PURGE`).
4. Run the carver again and confirm no files are recovered.
5. Download the generated certificate from the **Certificate Vault**.

---

## Running the tests

```bash
python test_engine.py
```

The script runs the full pipeline: creates a synthetic disk, reads a hex window, carves files, wipes the image, verifies the result, re-scans to confirm nothing is recoverable, and generates a PDF certificate.

---

## API reference

Interactive documentation is available at `/docs`.

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/status` | Platform status and engine information |
| GET | `/api/health` | Health check |
| GET | `/api/disks` | List virtual disk images |
| POST | `/api/disks/create-sample` | Create a sample evidence disk (`filename`, `size_mb`) |
| GET | `/api/hex-view` | Hex window of a disk (`disk_path`, `offset`, `length`) |
| POST | `/api/carve` | Carve recoverable files from a disk (`disk_path`) |
| POST | `/api/wipe` | Sanitize a disk and generate a certificate (`disk_path`, `standard`, `operator_name`) |
| GET | `/api/certificates` | List generated certificates |
| GET | `/api/certificates/{cert_id}/download` | Download a certificate PDF |
| GET | `/api/recovered/{disk_stem}/{filename}` | Download a carved file |
| GET | `/api/gemini/status` | Whether a Gemini key is configured |
| GET | `/api/gemini/presets` | Curated mystery-artifact presets |
| POST | `/api/gemini/unknown-search` | Analyze an unknown artifact |
| POST | `/api/gemini/case-assistant` | Ask the DFIR case assistant |
| POST | `/api/gemini/configure` | Set the Gemini API key at runtime |

### Example
```bash
# Create a sample disk
curl -X POST http://127.0.0.1:8085/api/disks/create-sample \
  -H "Content-Type: application/json" \
  -d '{"filename": "demo.img", "size_mb": 5}'

# Carve it
curl -X POST http://127.0.0.1:8085/api/carve \
  -H "Content-Type: application/json" \
  -d '{"disk_path": "<path returned by the previous call>"}'

# Wipe it (NIST Purge) and generate a certificate
curl -X POST http://127.0.0.1:8085/api/wipe \
  -H "Content-Type: application/json" \
  -d '{"disk_path": "<same path>", "standard": "NIST_PURGE", "operator_name": "Examiner"}'
```

---

## Project structure

```
ForensiX-platform/
├── engine/
│   ├── disk_manager.py           # Virtual disks, sample evidence, hex reader, safety boundary
│   ├── recovery_engine.py        # Raw-sector file carver
│   ├── wipe_engine.py            # Sanitization passes, entropy, verification
│   ├── certificate_generator.py  # PDF audit certificates
│   ├── gemini_service.py         # Gemini unknown-artifact search
│   └── case_assistant.py         # DFIR case assistant
├── static/
│   ├── index.html                # Landing page
│   ├── studio.html               # Forensic Studio
│   ├── styles.css                # UI styling
│   └── app.js                    # Frontend logic and API calls
├── api/
│   └── index.py                  # Vercel serverless entrypoint
├── data/
│   ├── disks/                    # Virtual disk images
│   ├── recovered/                # Carved files
│   └── certificates/             # Generated PDFs
├── server.py                     # FastAPI application
├── test_engine.py                # Pipeline test
├── requirements.txt
├── render.yaml                   # Render deployment config
├── vercel.json                   # Vercel routing config
└── SIH_BLUEPRINT.md              # Hackathon design document
```

---

## Deployment

### Render (backend and app)
1. Push the repository to GitHub.
2. In Render, choose **New → Blueprint** and select the repo (`render.yaml` is picked up automatically).
3. Add the `GEMINI_API_KEY` environment variable if you want live AI.
4. Deploy.

### Vercel
1. Import the repository on Vercel with the **Other** framework preset.
2. Deploy. `vercel.json` routes requests to `api/index.py`.

> On Vercel the filesystem is read-only apart from `/tmp`, so disks, recovered files and certificates are **temporary** and can disappear between requests. Use the Render deployment (or run locally) for a persistent demo.

To point the frontend at a separately hosted API, set `window.FORENSIX_API_URL` or the `forensix_api_base` value in the browser's local storage.

---

## Privacy note on AI features

When Gemini is enabled, requests are sent from the ForensiX server to Google's Gemini API. Depending on the feature, this can include:
- Hex snippets, magic bytes, hashes and free-text notes entered by the examiner (Unknown Artifact Search).
- Case details, artifact names and summaries, and the examiner's question (Case Assistant).

Do not enable live AI with real or sensitive evidence. Use the built-in simulated mode (no API key) for offline demos. Review Google's current API data-use terms for your key's tier before use.

Also note that `/api/gemini/configure` sets the key for the whole running server and has no authentication, so it is intended for local and demo use only.

---

## Limitations

- **Virtual images only.** Wiping and carving operate on files inside `data/disks/`. Physical drives are not supported and are blocked by design.
- **SSD Secure Erase is simulated.** It does not send ATA or NVMe firmware commands.
- **Entropy-based verification.** The wipe check samples sectors and compares against the expected pattern and entropy; it is not a full read-back of every sector for all modes.
- **Certificates are not digitally signed.** They include SHA-256 hashes and blank signature lines for manual sign-off. They are audit reports, not a legally validated instrument.
- **No authentication or multi-user support.** There are no accounts, roles or database.
- **Carver scope.** Four file families plus credential-style text blocks, with size limits per type.
- **AI answers are advisory.** Gemini output may be wrong. Verify findings independently, and note that the fallback mode returns pre-written responses.

---

## Standards referenced

- NIST SP 800-88 Rev. 1, *Guidelines for Media Sanitization* (Clear and Purge concepts)
- DoD 5220.22-M (legacy three-pass method; the standard has been withdrawn and is included for reference)

ForensiX implements methods **modeled on** these documents. It has not been independently tested, validated or certified against any standard.

---

## Team and acknowledgements

Developed for Smart India Hackathon 2026 (SIH26149).

- Repository: [PushkarNagarmote-stack/ForensiX-platform](https://github.com/PushkarNagarmote-stack/ForensiX-platform)
- Team members: *add names and roles here*

---

## License

No license file is currently included in the repository. Add one (for example MIT or Apache-2.0) before sharing or accepting contributions.
