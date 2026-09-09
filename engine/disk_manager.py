import os
import io
import struct
import hashlib
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

BASE_DIR = Path(__file__).resolve().parent.parent
BASE_DATA_DIR = Path("/tmp/forensix_data") if (os.environ.get("VERCEL") or not os.access(BASE_DIR, os.W_OK)) else BASE_DIR / "data"
DISKS_DIR = BASE_DATA_DIR / "disks"
try:
    DISKS_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

class SafetyException(Exception):
    """Raised when an unsafe disk operation is attempted."""
    pass

class DiskManager:
    """
    Manages safe virtual disk images (.img) and enforces strict safety isolation.
    Guarantees no host OS drives or physical storage devices can ever be modified.
    """

    SECTOR_SIZE = 512

    @staticmethod
    def is_safe_target(disk_path: str | Path) -> bool:
        """
        Enforce strict safety boundary: Only allow files within designated disks directory.
        """
        target = Path(disk_path).resolve()
        # Ensure it's not a device path and resides within our project's data directory
        disks_root = DISKS_DIR.resolve()
        try:
            target.relative_to(disks_root)
            return target.suffix.lower() in [".img", ".raw", ".bin"]
        except ValueError:
            return False

    @staticmethod
    def calculate_sha256(file_path: str | Path) -> str:
        """Calculate SHA-256 hash of the disk image."""
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                sha256.update(chunk)
        return sha256.hexdigest()

    @staticmethod
    def inspect_disk_status(file_path: Path) -> Dict[str, Any]:
        """
        Inspect disk image to detect if it contains intact synthetic evidence
        or has been wiped / sanitized.
        """
        try:
            total_size = file_path.stat().st_size
            if total_size == 0:
                return {"status": "EMPTY", "label": "Empty (0 KB)", "evidence_count": 0}

            with open(file_path, "rb") as f:
                # Check JPEG header at Sector 2048 (offset 1048576)
                if total_size >= 1048576 + 4:
                    f.seek(1048576)
                    hdr_jpeg = f.read(3)
                    if hdr_jpeg == b"\xFF\xD8\xFF":
                        return {
                            "status": "EVIDENCE_ACTIVE",
                            "label": "Evidence Loaded (5 Artifacts)",
                            "evidence_count": 5
                        }

                # Check PNG header at Sector 3500 (offset 1792000)
                if total_size >= 1792000 + 8:
                    f.seek(1792000)
                    hdr_png = f.read(4)
                    if hdr_png == b"\x89PNG":
                        return {
                            "status": "EVIDENCE_ACTIVE",
                            "label": "Evidence Loaded (Active)",
                            "evidence_count": 4
                        }

                # Sample first 4KB to check if zeroed or pattern
                f.seek(0)
                sample = f.read(min(4096, total_size))
                if sample.strip(b"\x00") == b"":
                    return {
                        "status": "SANITIZED",
                        "label": "Sanitized (0.0000 H • Zeroed)",
                        "evidence_count": 0
                    }

            return {
                "status": "SANITIZED",
                "label": "Sanitized (Overwritten)",
                "evidence_count": 0
            }
        except Exception:
            return {"status": "UNKNOWN", "label": "Raw Media", "evidence_count": 0}

    @staticmethod
    def ensure_default_evidence_disk() -> Dict[str, Any]:
        """Ensure that at least one evidence-packed disk exists for instant demonstration."""
        default_target = DISKS_DIR / "sih_evidence_drive.img"
        need_create = True
        if default_target.exists():
            status = DiskManager.inspect_disk_status(default_target)
            if status["status"] == "EVIDENCE_ACTIVE":
                need_create = False

        if need_create:
            return DiskManager.create_sample_disk("sih_evidence_drive.img", size_mb=5)
        return {
            "name": default_target.name,
            "path": str(default_target),
            "size_bytes": default_target.stat().st_size,
            "size_mb": 5,
            "sha256": DiskManager.calculate_sha256(default_target)
        }

    @staticmethod
    def list_disks() -> List[Dict[str, Any]]:
        """
        List all available virtual disk images and their metadata.
        Intelligently prioritizes active evidence drives first, followed by sanitized ones.
        """
        # Ensure at least one evidence disk is ready
        DiskManager.ensure_default_evidence_disk()

        disks = []
        for file in DISKS_DIR.glob("*.img"):
            stat = file.stat()
            inspection = DiskManager.inspect_disk_status(file)
            disks.append({
                "name": file.name,
                "path": str(file),
                "size_bytes": stat.st_size,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "modified": stat.st_mtime,
                "sha256": DiskManager.calculate_sha256(file),
                "status": inspection["status"],
                "status_label": inspection["label"],
                "evidence_count": inspection["evidence_count"]
            })

        # Sort: EVIDENCE_ACTIVE drives first (newest modified first), then SANITIZED drives
        disks.sort(key=lambda d: (0 if d["status"] == "EVIDENCE_ACTIVE" else 1, -d["modified"]))
        return disks

    @staticmethod
    def create_synthetic_evidence_files() -> Dict[str, bytes]:
        """
        Generate realistic binary evidence files:
        1. Confidential JPEG with visible watermark
        2. Secret PNG badge
        3. Classified investigation PDF report
        4. Sensitive credentials text log
        5. Internal corporate memo ZIP
        """
        files = {}

        # 1. JPEG image
        img_jpeg = Image.new("RGB", (400, 250), color=(18, 24, 38))
        draw_jpeg = ImageDraw.Draw(img_jpeg)
        draw_jpeg.rectangle([10, 10, 390, 240], outline=(239, 68, 68), width=3)
        draw_jpeg.text((30, 30), "FORENSIC CASE #9902", fill=(239, 68, 68))
        draw_jpeg.text((30, 65), "EVIDENCE ARTIFACT - DO NOT DISTRIBUTE", fill=(243, 244, 246))
        draw_jpeg.text((30, 100), "Financial Ledger Screenshot [CONFIDENTIAL]", fill=(147, 197, 253))
        draw_jpeg.text((30, 140), "Target: Offshore Account #CH-9921-884", fill=(52, 211, 153))
        draw_jpeg.text((30, 180), "Timestamp: 2026-09-05 18:22:10 UTC", fill=(156, 163, 175))
        buf_jpeg = io.BytesIO()
        img_jpeg.save(buf_jpeg, format="JPEG", quality=90)
        files["case_evidence_9902.jpg"] = buf_jpeg.getvalue()

        # 2. PNG badge
        img_png = Image.new("RGBA", (300, 160), color=(15, 23, 42, 255))
        draw_png = ImageDraw.Draw(img_png)
        draw_png.ellipse([10, 10, 80, 80], outline=(6, 182, 212), width=3)
        draw_png.text((95, 30), "SECURITY TOKEN ID", fill=(6, 182, 212))
        draw_png.text((95, 60), "TOKEN: 9f8a-44c2-bf71", fill=(226, 232, 240))
        draw_png.text((20, 110), "BIOMETRIC AUTH PASSED: LEVEL 5", fill=(16, 185, 129))
        buf_png = io.BytesIO()
        img_png.save(buf_png, format="PNG")
        files["auth_token_badge.png"] = buf_png.getvalue()

        # 3. PDF Classified Report
        buf_pdf = io.BytesIO()
        c = canvas.Canvas(buf_pdf, pagesize=letter)
        c.setTitle("Classified Forensics Report")
        c.setAuthor("ForensiX Forensic Investigator")
        c.drawString(50, 750, "CONFIDENTIAL INVESTIGATION DOSSIER - SPECIAL OPERATIONS")
        c.drawString(50, 730, "----------------------------------------------------------------------------------------------------")
        c.drawString(50, 700, "Subject: Unauthorized Data Exfiltration via USB Mass Storage Device")
        c.drawString(50, 680, "Case ID: FORENSIX-SIH-2026-X88")
        c.drawString(50, 660, "Suspect Machine: WS-NODE-ALPHA (LBA sectors: 4096-16384)")
        c.drawString(50, 630, "Summary of Findings:")
        c.drawString(70, 610, "1. Targeted exfiltration detected at 02:14 AM.")
        c.drawString(70, 590, "2. User attempted rapid shift-delete of 14 corporate documents.")
        c.drawString(70, 570, "3. MBR partition table partially zeroed to foil standard recovery.")
        c.drawString(70, 550, "4. Deep carving reconstructed original payload.")
        c.drawString(50, 500, "CONFIDENTIALITY NOTICE: This document contains restricted law enforcement data.")
        c.showPage()
        c.save()
        files["incident_dossier.pdf"] = buf_pdf.getvalue()

        # 4. Sensitive credentials text log
        files["server_credentials.txt"] = (
            "--- CLASSIFIED INFRASTRUCTURE CREDENTIALS ---\n"
            "GENERATED: 2026-09-05T12:00:00Z\n"
            "ROOT_DATABASE_HOST=postgres-cluster.internal.net:5432\n"
            "ROOT_USERNAME=admin_forensix\n"
            "ROOT_PASSWORD=K8#v9X$mP2!qL990zW\n"
            "JWT_SIGNING_SECRET=ec892e85a0c0b9f074ef9f61b0c031c2d95e0\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "EMERGENCY_DESTRUCTION_KEY=SEC-PURGE-9981-DO-NOT-SHARE\n"
        ).encode("utf-8")

        # 5. Secret Memo ZIP
        buf_zip = io.BytesIO()
        with zipfile.ZipFile(buf_zip, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("secret_memo.txt", "This archive proves recovery of compressed containers from raw sectors.")
            zf.writestr("passwords.csv", "service,user,pass\ngithub,devops,ghp_TestSecretKey123456\n")
        files["classified_archive.zip"] = buf_zip.getvalue()

        return files

    @staticmethod
    def create_sample_disk(filename: str = "forensic_demo_drive.img", size_mb: int = 5) -> Dict[str, Any]:
        """
        Create a realistic virtual disk image populated with:
        - MBR / Partition Table Header simulation at Sector 0
        - Synthetic filesystem root directory
        - Evidence files seeded at varied sector offsets
        - Residual / unallocated space simulating deleted files
        """
        if not filename.endswith(".img"):
            filename += ".img"

        target_path = DISKS_DIR / filename
        total_bytes = size_mb * 1024 * 1024

        # Initialise disk with empty/randomized background noise
        # To simulate a previously used drive, we fill with low-entropy pseudo-pattern
        with open(target_path, "wb") as f:
            # Write simulated MBR boot record (512 bytes)
            mbr = bytearray(512)
            mbr[0:4] = b"\xEB\x3C\x90\x00"
            mbr[446:446+16] = struct.pack("<BBBBBBBBII", 0x80, 0x01, 0x01, 0x00, 0x07, 0xFE, 0xFF, 0xFF, 2048, (total_bytes // 512) - 2048)
            mbr[510:512] = b"\x55\xAA"
            f.write(mbr)

            # Fill remaining size up to total_bytes
            remaining = total_bytes - 512
            chunk_size = 1024 * 64
            blank_block = b"\x00" * chunk_size
            while remaining > 0:
                to_write = min(remaining, chunk_size)
                f.write(blank_block[:to_write])
                remaining -= to_write

        # Now inject evidence files at distinct sector offsets
        evidence_files = DiskManager.create_synthetic_evidence_files()
        
        # Sector offsets (spaced safely across the 5MB disk)
        offsets = [
            2048 * 512,        # 1 MB offset (JPEG)
            3500 * 512,        # ~1.7 MB offset (PNG)
            5000 * 512,        # ~2.4 MB offset (PDF)
            7000 * 512,        # ~3.4 MB offset (TXT)
            8200 * 512         # ~4.0 MB offset (ZIP)
        ]

        injected_records = []
        with open(target_path, "r+b") as f:
            for (fname, data), offset in zip(evidence_files.items(), offsets):
                f.seek(offset)
                f.write(data)
                injected_records.append({
                    "filename": fname,
                    "offset_bytes": offset,
                    "sector": offset // 512,
                    "size_bytes": len(data)
                })

        sha256 = DiskManager.calculate_sha256(target_path)
        return {
            "name": filename,
            "path": str(target_path),
            "size_bytes": total_bytes,
            "size_mb": size_mb,
            "sha256": sha256,
            "injected_files": injected_records
        }

    @staticmethod
    def read_hex_window(disk_path: str | Path, offset: int = 0, length: int = 256) -> Dict[str, Any]:
        """
        Read a window of raw bytes formatted as Hex + ASCII for the live hex viewer.
        """
        if not DiskManager.is_safe_target(disk_path):
            raise SafetyException(f"Access denied: '{disk_path}' is not a permitted virtual disk.")

        total_size = os.path.getsize(disk_path)
        offset = max(0, min(offset, total_size))
        length = min(length, total_size - offset)

        with open(disk_path, "rb") as f:
            f.seek(offset)
            raw = f.read(length)

        # Format into 16-byte rows
        rows = []
        for i in range(0, len(raw), 16):
            chunk = raw[i:i+16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            # Pad hex string to 48 characters if less than 16 bytes
            hex_part = f"{hex_part:<47}"
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            rows.append({
                "offset": f"{offset + i:08X}",
                "hex": hex_part,
                "ascii": ascii_part
            })

        return {
            "disk_path": str(disk_path),
            "total_size": total_size,
            "offset": offset,
            "length": length,
            "rows": rows
        }
