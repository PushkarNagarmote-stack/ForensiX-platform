# ForensiX | Certified Media Sanitization & Deep Raw Sector File Recovery OS

Official **Smart India Hackathon (SIH 2026)** Solution for **PS-DFIR-04**.

ForensiX is an air-gapped, dual-loop cyber-forensic platform combining **deep raw sector file carving** (JPEG, PNG, PDF, ZIP, and sensitive forensic documents) with **cryptographically verified data sanitization** compliant with NIST SP 800-88 Rev. 1 and DoD 5220.22-M standards.

---

## 🌟 Key Architecture & Capabilities

### 1. Dual-Loop Forensic Lifecycle
- **Loop 1: Deep File Recovery & Carving**:
  - Raw byte header/footer parser that bypasses corrupted or zeroed filesystem allocation tables (FAT/NTFS/EXT4).
  - Hex preview, MD5/SHA-256 custody chain hashing, and instant file extraction.
- **Loop 2: Certified Media Sanitization**:
  - **NIST SP 800-88 Rev. 1 (Clear)**: 1-Pass logical overwrite + sector verification.
  - **NIST SP 800-88 Rev. 1 (Purge)**: 3-Pass cryptographic pseudo-random overwrite with bitwise inversion.
  - **DoD 5220.22-M (E)**: 3-Pass standard (zeros, ones, pseudo-random bytes + verification).
  - **SSD Firmware Sanitization**: ATA Secure Erase emulation.
- **Shannon Entropy Telemetry**: Real-time mathematical proof showing entropy drop to `0.0000 bits/byte` confirming zero residual data leakage.
- **ReportLab PDF Certificates**: Tamper-proof, cryptographically signed sanitization certificates ready for court submission.

### 2. Modern Glassmorphic Forensic Interface
- **Dark Emerald & Obsidian Aesthetic**: Inspired by organic glassmorphic design systems (Sylva design language).
- **VisionOS Floating Navigation Dock**: Quick-switch between Deep Carver, Sanitizer, Live Hex Inspector, Certificate Vault, SIH Defense Matrix, and Gemini DFIR Copilot.
- **Responsive Engineering**: Optimized for desktop multi-monitor command stations with adaptive mobile accessibility.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- Modern Web Browser (Chrome, Edge, Firefox, Safari)

### Installation
```bash
# Clone the repository
git clone https://github.com/pushkarnagarmote/forensix-platform.git
cd forensix-platform

# Install dependencies
pip install -r requirements.txt
```

### Running ForensiX Locally
```bash
python server.py
```
Open your browser and navigate to:
- **Landing Overview**: [http://127.0.0.1:8085](http://127.0.0.1:8085)
- **Forensic Studio**: [http://127.0.0.1:8085/studio](http://127.0.0.1:8085/studio)

---

## 🧪 Running Automated Tests
```bash
python test_engine.py
```

---

## 📁 Repository Structure
```
forensix-platform/
├── engine/
│   ├── disk_manager.py          # Virtual disk generation & mounting
│   ├── recovery_engine.py       # Raw sector file carver
│   ├── wipe_engine.py           # NIST SP 800-88 & DoD wiping algorithms
│   ├── certificate_generator.py # Court-admissible PDF generation
│   ├── gemini_service.py        # Gemini 3.7 Flash unknown artifact search
│   └── case_assistant.py        # Forensic case Copilot
├── static/
│   ├── index.html               # Product landing page & problem defense
│   ├── studio.html              # Interactive forensic studio
│   ├── styles.css               # Sylva glassmorphic design system
│   └── app.js                   # Client controller & Web Audio haptics
├── data/
│   ├── disks/                   # Evidence drive images (.gitkeep)
│   ├── recovered/               # Carved artifacts (.gitkeep)
│   └── certificates/            # Issued PDF certificates (.gitkeep)
├── server.py                    # FastAPI server
├── requirements.txt             # Python dependencies
└── test_engine.py               # Engine unit tests
```

---

## ⚖️ License & Compliance
Compliant with **NIST SP 800-88 Rev. 1 Guidelines for Media Sanitization** and **DoD 5220.22-M National Industrial Security Program Operating Manual (NISPOM)**.
