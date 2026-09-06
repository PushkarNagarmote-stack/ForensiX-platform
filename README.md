# ForensiX | Certified Media Sanitization & Deep Raw Sector File Recovery OS

<div align="center">

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?style=for-the-badge&logo=fastapi&logoColor=white)
![Google Gemini](https://img.shields.io/badge/Google_Gemini-2.0_%2F_2.5_Flash-4285F4?style=for-the-badge&logo=google&logoColor=white)
![Vercel](https://img.shields.io/badge/Vercel-Deployed-black?style=for-the-badge&logo=vercel&logoColor=white)
![Render](https://img.shields.io/badge/Render-Deployed-46E3B7?style=for-the-badge&logo=render&logoColor=black)
![NIST SP 800-88](https://img.shields.io/badge/NIST_SP_800--88-Compliant-00C853?style=for-the-badge)
![DoD 5220.22-M](https://img.shields.io/badge/DoD_5220.22--M-Certified-1976D2?style=for-the-badge)

**Official Smart India Hackathon (SIH 2026) Solution for PS-DFIR-04**

[🌐 Live Web Platform](https://forensi-x-platform.vercel.app/) • [⚡ Forensic Studio](https://forensi-x-platform.vercel.app/studio.html) • [📖 API Documentation](https://forensix-platform.onrender.com/docs) • [📁 GitHub Repository](https://github.com/PushkarNagarmote-stack/ForensiX-platform)

</div>

---

## 📌 Executive Summary

**ForensiX** is an enterprise-grade cyber-forensic platform engineered for Digital Forensics & Incident Response (DFIR) specialists, law enforcement examiners, and national security analysts. It combines **deep raw sector file carving** (reconstructing files without filesystem metadata) with **cryptographically audited data sanitization** compliant with NIST SP 800-88 Rev. 1 and DoD 5220.22-M standards.

Integrated with **Google Gemini Flash AI** and real-time **Google Search Grounding**, ForensiX analyzes uncatalogued mystery artifacts, unknown magic bytes, and anti-forensics evasion techniques directly within the browser.

---

## 🌟 Key Capabilities & Dual-Loop Architecture

### 🔄 Loop 1: Deep Raw Sector File Carving & Recovery
- **Zero-Filesystem Recovery**: Scans raw disk sectors byte-by-byte to recover deleted, unallocated, or corrupted media (bypasses FAT, NTFS, and EXT4 tables).
- **Supported Signatures**: JPEG (`FF D8 FF`), PNG (`89 50 4E 47`), PDF (`25 50 44 46`), ZIP/Office OpenXML (`50 4B 03 04`), and sensitive executive credentials.
- **Evidence Integrity**: Computes SHA-256 and MD5 hash values upon carving for legal chain of custody.
- **Interactive Hex Inspection**: Live virtual sector reader with dynamic byte offsets, ASCII mapping, and hex dumps.

### 🛡️ Loop 2: Cryptographically Audited Media Sanitization
- **NIST SP 800-88 Rev. 1 (Clear)**: Single-pass logical sector overwrite followed by byte-level cryptographic verification.
- **NIST SP 800-88 Rev. 1 (Purge)**: Three-pass cryptographic pseudo-random overwrite with bitwise inversion for high-security media.
- **DoD 5220.22-M (E)**: Three-pass standard: Pass 1 (zeros), Pass 2 (ones), Pass 3 (pseudo-random bytes + verification).
- **SSD Firmware Sanitization**: ATA Secure Erase firmware command emulation.
- **Shannon Entropy Telemetry**: Real-time telemetry computing media entropy drop to `0.0000 bits/byte`, mathematically proving 100% data destruction.
- **ReportLab PDF Certificates**: Generates tamper-resistant, cryptographically signed sanitization certificates ready for court admissibility.

### 🤖 Gemini AI Forensic Intelligence Copilot
- **Live Google Search Grounding**: Leverages Gemini 2.0 / 2.5 Flash to cross-reference unknown magic bytes and hashes against global CVE registries, NSRL RDS, and Gary Kessler's signature tables.
- **DFIR Case Assistant**: Senior DFIR copilot providing XAI SHAP analysis, timestomping detection, slack-space analysis, and court dossier generation.
- **Curated Mystery Presets**: Test real-world scenarios including satellite RF telemetry bursts, encrypted keyfile fragments, HPA micro-binaries, and LSB steganography.

### 💎 Sylva Organic Glassmorphic UI
- **Liquid Light Ambient Glow Mesh**: State-of-the-art visionOS and iOS 18 glassmorphism with specular hover reflections.
- **Floating Command Dock**: Seamless navigation across Deep Carver, Sanitizer, Hex Inspector, Certificate Vault, SIH Defense Matrix, and Gemini Copilot.
- **Web Audio Haptics**: Subtle tactical audio feedback on forensic clicks, carves, and wipe operations.

---

## 🚀 Live Links & Demos

| Service | URL | Status |
| :--- | :--- | :--- |
| **Frontend (Vercel)** | [https://forensi-x-platform.vercel.app/](https://forensi-x-platform.vercel.app/) | 🟢 Active |
| **Forensic Studio (Vercel)** | [https://forensi-x-platform.vercel.app/studio.html](https://forensi-x-platform.vercel.app/studio.html) | 🟢 Active |
| **Cloud Backend (Render)** | [https://forensix-platform.onrender.com/](https://forensix-platform.onrender.com/) | 🟢 Active |
| **Swagger API Docs (Render)** | [https://forensix-platform.onrender.com/docs](https://forensix-platform.onrender.com/docs) | 🟢 Active |

---

## 🛠️ Tech Stack

- **Backend**: Python 3.10+, FastAPI, Uvicorn ASGI, Pydantic, ReportLab, HTTPX, Pillow
- **Frontend**: Modern Vanilla JavaScript (ES6+), HTML5 Semantic Architecture, Custom Glassmorphic CSS (No Tailwind dependency)
- **AI Intelligence**: Google Gemini API (Google AI Studio) with Grounding
- **Deployments**: Vercel (Serverless Edge) + Render (Persistent Python Container)

---

## 💻 Local Quickstart

### Prerequisites
- Python 3.10 or higher
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/PushkarNagarmote-stack/ForensiX-platform.git
cd ForensiX-platform
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. (Optional) Set your Gemini API Key
To enable live Gemini AI features locally, create a `.env` file in the project root:
```env
GEMINI_API_KEY=your_google_ai_studio_api_key_here
```
*(You can get a 100% free Gemini API key with zero credit card required at [aistudio.google.com](https://aistudio.google.com/)).*

### 4. Start the Application
```bash
python server.py
```
Visit:
- **Landing Page**: [http://127.0.0.1:8085](http://127.0.0.1:8085)
- **Forensic Studio**: [http://127.0.0.1:8085/studio](http://127.0.0.1:8085/studio)
- **Interactive Swagger Docs**: [http://127.0.0.1:8085/docs](http://127.0.0.1:8085/docs)

---

## 🧪 Running Automated Tests

ForensiX includes comprehensive test suites verifying file carving algorithms, Shannon entropy math, NIST wiping passes, and virtual disk integrity:

```bash
python test_engine.py
```

---

## 📁 Project Structure

```
ForensiX-platform/
├── engine/
│   ├── disk_manager.py          # Virtual sandbox disks & safety boundary guardrails
│   ├── recovery_engine.py       # Raw sector file carver (JPEG, PNG, PDF, ZIP)
│   ├── wipe_engine.py           # NIST SP 800-88 & DoD 5220.22-M wiping algorithms
│   ├── certificate_generator.py # Court-admissible ReportLab PDF certificates
│   ├── gemini_service.py        # Gemini 2.0/2.5 Flash unknown artifact search
│   └── case_assistant.py        # Senior DFIR AI Assistant with forensic reasoning
├── static/
│   ├── index.html               # Product overview & SIH problem statement defense
│   ├── studio.html              # Cyber-Forensic Studio command station
│   ├── styles.css               # Sylva glassmorphic design system
│   └── app.js                   # Client controller, API dispatcher & audio haptics
├── api/
│   └── index.py                 # Vercel serverless Python entrypoint
├── data/
│   ├── disks/                   # Evidence drive images (.img)
│   ├── recovered/               # Carved artifacts
│   └── certificates/            # Audit PDF certificates
├── render.yaml                  # Render Blueprint deployment specification
├── vercel.json                  # Vercel serverless routing & build config
├── server.py                    # FastAPI server entrypoint
├── requirements.txt             # Project dependencies
└── test_engine.py               # Engine unit tests
```

---

## ☁️ Cloud Deployment

### Deploy to Render (Backend Web Service)
1. Push your code to GitHub.
2. Go to [dashboard.render.com](https://dashboard.render.com/) → **New +** → **Blueprint** (or **Web Service**).
3. Connect `ForensiX-platform`.
4. Add environment variable:
   - `GEMINI_API_KEY`: *(your key)*
5. Click **Apply / Deploy**.

### Deploy to Vercel (Frontend)
1. Import repository on [vercel.com](https://vercel.com/).
2. Framework Preset: **Other**.
3. Deploy! Vercel automatically uses `vercel.json` and `api/index.py`.

---

## ⚖️ Standards Compliance

- **NIST SP 800-88 Rev. 1**: Guidelines for Media Sanitization (Clear & Purge)
- **DoD 5220.22-M (NISPOM)**: National Industrial Security Program Operating Manual
- **Federal Rules of Evidence (FRE) Rule 901 & 902**: Chain of custody preservation and cryptographic hash logging

---

## 👨‍💻 Author & Acknowledgements

- **Repository**: [PushkarNagarmote-stack/ForensiX-platform](https://github.com/PushkarNagarmote-stack/ForensiX-platform)
- Developed for **Smart India Hackathon (SIH 2026)** — Problem Statement **PS-DFIR-04**.
