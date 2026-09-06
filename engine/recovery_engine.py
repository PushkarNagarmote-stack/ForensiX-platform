import os
import io
import re
import hashlib
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional
from PIL import Image
from engine.disk_manager import DiskManager, SafetyException
from engine.wipe_engine import WipeEngine

BASE_DIR = Path(__file__).resolve().parent.parent
RECOVERED_DIR = BASE_DIR / "data" / "recovered"
RECOVERED_DIR.mkdir(parents=True, exist_ok=True)

class RecoveryEngine:
    """
    Forensic Signature-Based File Carver.
    Reconstructs lost, deleted, and unallocated files directly from raw byte streams.
    """

    SIGNATURES = {
        "JPEG": {
            "header": b"\xFF\xD8\xFF",
            "footer": b"\xFF\xD9",
            "ext": ".jpg",
            "mime": "image/jpeg",
            "max_size": 10 * 1024 * 1024
        },
        "PNG": {
            "header": b"\x89PNG\r\n\x1a\n",
            "footer": b"IEND\xAEB\x60\x82",
            "ext": ".png",
            "mime": "image/png",
            "max_size": 10 * 1024 * 1024
        },
        "PDF": {
            "header": b"%PDF",
            "footer": b"%%EOF",
            "ext": ".pdf",
            "mime": "application/pdf",
            "max_size": 15 * 1024 * 1024
        },
        "ZIP": {
            "header": b"PK\x03\x04",
            "footer": b"PK\x05\x06",
            "ext": ".zip",
            "mime": "application/zip",
            "max_size": 25 * 1024 * 1024
        }
    }

    @staticmethod
    def carve_disk(
        disk_path: str | Path,
        progress_callback: Optional[callable] = None
    ) -> Dict[str, Any]:
        """
        Perform deep sector scan across disk_path and carve intact files.
        """
        if not DiskManager.is_safe_target(disk_path):
            raise SafetyException(f"Safety restriction: '{disk_path}' is outside designated virtual sandbox.")

        disk_path = Path(disk_path)
        disk_name = disk_path.name
        output_dir = RECOVERED_DIR / disk_path.stem
        output_dir.mkdir(parents=True, exist_ok=True)

        total_size = os.path.getsize(disk_path)
        recovered_files: List[Dict[str, Any]] = []

        # Read disk in memory/stream chunks
        with open(disk_path, "rb") as f:
            raw_data = f.read()

        file_counter = 1

        # 1. Carve binary signature-based files
        for ftype, sig in RecoveryEngine.SIGNATURES.items():
            header = sig["header"]
            footer = sig["footer"]
            ext = sig["ext"]
            mime = sig["mime"]
            max_size = sig["max_size"]

            start_pos = 0
            while True:
                idx = raw_data.find(header, start_pos)
                if idx == -1:
                    break

                # Found header, search for footer
                file_end = -1
                if ftype == "ZIP":
                    # For zip, find End of Central Directory (EOCD)
                    eocd_idx = raw_data.find(footer, idx)
                    if eocd_idx != -1 and (eocd_idx - idx) < max_size:
                        # EOCD record is minimum 22 bytes
                        file_end = eocd_idx + 22
                elif footer:
                    footer_idx = raw_data.find(footer, idx + len(header))
                    if footer_idx != -1 and (footer_idx - idx) < max_size:
                        file_end = footer_idx + len(footer)
                else:
                    file_end = idx + 4096  # fallback

                if file_end != -1 and file_end <= len(raw_data):
                    extracted_bytes = raw_data[idx:file_end]
                    
                    # Validate integrity
                    valid = False
                    confidence = 70
                    validation_msg = "Signature matched"

                    if ftype in ["JPEG", "PNG"]:
                        try:
                            im = Image.open(io.BytesIO(extracted_bytes))
                            im.verify()
                            valid = True
                            confidence = 98
                            validation_msg = f"Valid image parsed successfully ({im.format}, {im.size[0]}x{im.size[1]})"
                        except Exception as e:
                            valid = False
                            confidence = 45
                            validation_msg = f"Partial/Corrupted Image: {str(e)[:40]}"
                    elif ftype == "PDF":
                        if b"/Root" in extracted_bytes or b"/Pages" in extracted_bytes:
                            valid = True
                            confidence = 95
                            validation_msg = "Valid PDF document structure identified"
                        else:
                            confidence = 75
                            validation_msg = "PDF header/footer present; partial structure"
                    elif ftype == "ZIP":
                        try:
                            with zipfile.ZipFile(io.BytesIO(extracted_bytes)) as zf:
                                namelist = zf.namelist()
                                valid = True
                                confidence = 99
                                validation_msg = f"Valid archive with {len(namelist)} entries: {', '.join(namelist[:2])}"
                        except Exception as e:
                            confidence = 40
                            validation_msg = f"Archive validation error: {str(e)[:40]}"

                    # Save carved file
                    out_name = f"carved_{file_counter:03d}_{ftype.lower()}{ext}"
                    out_path = output_dir / out_name
                    with open(out_path, "wb") as out_f:
                        out_f.write(extracted_bytes)

                    entropy = WipeEngine.calculate_shannon_entropy(extracted_bytes)
                    sha256 = hashlib.sha256(extracted_bytes).hexdigest()

                    recovered_files.append({
                        "id": file_counter,
                        "filename": out_name,
                        "file_type": ftype,
                        "mime_type": mime,
                        "sector_offset": idx // DiskManager.SECTOR_SIZE,
                        "byte_offset": idx,
                        "size_bytes": len(extracted_bytes),
                        "size_kb": round(len(extracted_bytes) / 1024, 2),
                        "sha256": sha256,
                        "entropy": entropy,
                        "confidence_percent": confidence,
                        "status": "Intact" if confidence > 80 else "Partial",
                        "validation_msg": validation_msg,
                        "path": str(out_path),
                        "web_url": f"/api/recovered/{disk_path.stem}/{out_name}"
                    })
                    file_counter += 1
                    start_pos = file_end
                else:
                    start_pos = idx + len(header)

        # 2. Carve sensitive plaintext / credential blocks
        cred_header = b"--- CLASSIFIED"
        idx_txt = raw_data.find(cred_header)
        if idx_txt != -1:
            end_txt = raw_data.find(b"\n\x00", idx_txt)
            if end_txt == -1:
                end_txt = min(len(raw_data), idx_txt + 1024)
            txt_bytes = raw_data[idx_txt:end_txt].rstrip(b"\x00")
            if len(txt_bytes) > 20:
                out_name = f"carved_{file_counter:03d}_credentials.txt"
                out_path = output_dir / out_name
                with open(out_path, "wb") as out_f:
                    out_f.write(txt_bytes)
                
                recovered_files.append({
                    "id": file_counter,
                    "filename": out_name,
                    "file_type": "TEXT_CREDENTIALS",
                    "mime_type": "text/plain",
                    "sector_offset": idx_txt // DiskManager.SECTOR_SIZE,
                    "byte_offset": idx_txt,
                    "size_bytes": len(txt_bytes),
                    "size_kb": round(len(txt_bytes) / 1024, 2),
                    "sha256": hashlib.sha256(txt_bytes).hexdigest(),
                    "entropy": WipeEngine.calculate_shannon_entropy(txt_bytes),
                    "confidence_percent": 99,
                    "status": "Intact",
                    "validation_msg": "Plaintext credential key-pairs recovered from raw sectors",
                    "path": str(out_path),
                    "web_url": f"/api/recovered/{disk_path.stem}/{out_name}"
                })
                file_counter += 1

        return {
            "disk_name": disk_name,
            "total_bytes_scanned": total_size,
            "sectors_scanned": total_size // DiskManager.SECTOR_SIZE,
            "total_recovered": len(recovered_files),
            "recovered_files": recovered_files
        }
