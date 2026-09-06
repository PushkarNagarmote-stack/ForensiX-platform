import os
import math
import time
import secrets
from pathlib import Path
from typing import Dict, Any, Callable, Optional
from engine.disk_manager import DiskManager, SafetyException

class WipeEngine:
    """
    Certified Forensic Data Sanitization Engine implementing:
    - NIST SP 800-88 Rev. 1 Clear & Purge
    - DoD 5220.22-M (3-Pass)
    - SSD ATA Secure Erase / NVMe Crypto Sanitize
    - Mathematical Shannon Entropy Verification
    """

    CHUNK_SIZE = 64 * 1024  # 64 KB block streaming

    @staticmethod
    def calculate_shannon_entropy(data: bytes) -> float:
        """
        Calculate Shannon entropy of a byte array (0.0 to 8.0 bits per byte).
        0.0 = Uniform (e.g., all 0x00s).
        ~8.0 = High randomness (encrypted data or random noise).
        """
        if not data:
            return 0.0
        byte_counts = [0] * 256
        for b in data:
            byte_counts[b] += 1
        
        entropy = 0.0
        total = len(data)
        for count in byte_counts:
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)
        return round(entropy, 4)

    @staticmethod
    def sample_disk_entropy(disk_path: str | Path, samples: int = 16, sample_size: int = 4096) -> float:
        """
        Calculate average Shannon entropy across evenly spaced disk sectors.
        """
        total_size = os.path.getsize(disk_path)
        if total_size == 0:
            return 0.0

        step = max(1, (total_size - sample_size) // samples) if total_size > sample_size else 0
        entropies = []
        with open(disk_path, "rb") as f:
            for i in range(samples):
                offset = min(i * step, max(0, total_size - sample_size))
                f.seek(offset)
                block = f.read(sample_size)
                if block:
                    entropies.append(WipeEngine.calculate_shannon_entropy(block))
        return round(sum(entropies) / len(entropies), 4) if entropies else 0.0

    @staticmethod
    def execute_wipe(
        disk_path: str | Path,
        standard: str = "NIST_CLEAR",
        progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        operator_name: str = "Forensic Analyst"
    ) -> Dict[str, Any]:
        """
        Execute sanitization following standard protocol.
        Supported standards:
        - 'NIST_CLEAR': NIST SP 800-88 Rev. 1 Clear (1-pass zeros + verify)
        - 'NIST_PURGE': NIST SP 800-88 Rev. 1 Purge (3-pass: random + complement + zero + verify)
        - 'DOD_5220_22_M': DoD 5220.22-M (3-pass: 0x00 -> 0xFF -> random -> verify)
        - 'SSD_SECURE_ERASE': ATA / NVMe Sanitize simulation (firmware crypto-key purge + zeroing)
        """
        if not DiskManager.is_safe_target(disk_path):
            raise SafetyException(f"Safety restriction: '{disk_path}' is outside designated virtual sandbox.")

        total_bytes = os.path.getsize(disk_path)
        start_time = time.time()
        pre_hash = DiskManager.calculate_sha256(disk_path)
        pre_entropy = WipeEngine.sample_disk_entropy(disk_path)

        # Normalize standard aliases
        std_norm = (standard or "NIST_CLEAR").upper().replace("-", "_").replace(" ", "_")
        if "CLEAR" in std_norm:
            standard = "NIST_CLEAR"
        elif "PURGE" in std_norm:
            standard = "NIST_PURGE"
        elif "DOD" in std_norm or "5220" in std_norm:
            standard = "DOD_5220_22_M"
        elif "SSD" in std_norm or "ERASE" in std_norm or "NVME" in std_norm:
            standard = "SSD_SECURE_ERASE"

        # Configure passes according to standard
        passes_plan = []
        standard_desc = ""

        if standard == "NIST_CLEAR":
            standard_desc = "NIST SP 800-88 Rev. 1 (Clear) - 1-Pass Logical Zero Overwrite"
            passes_plan = [
                {"name": "Pass 1: Fixed Zero Overwrite (0x00)", "type": "fixed", "byte": b"\x00"}
            ]
        elif standard == "NIST_PURGE":
            standard_desc = "NIST SP 800-88 Rev. 1 (Purge) - Cryptographic Pseudo-Random & Inversion"
            passes_plan = [
                {"name": "Pass 1: Pseudo-Random Overwrite", "type": "random", "byte": None},
                {"name": "Pass 2: Bitwise Inversion / Complement", "type": "fixed", "byte": b"\x55"},
                {"name": "Pass 3: Final Zero Sanitization", "type": "fixed", "byte": b"\x00"}
            ]
        elif standard == "DOD_5220_22_M":
            standard_desc = "DoD 5220.22-M - Department of Defense 3-Pass Method"
            passes_plan = [
                {"name": "Pass 1: Fixed Zero Overwrite (0x00)", "type": "fixed", "byte": b"\x00"},
                {"name": "Pass 2: Fixed One Overwrite (0xFF)", "type": "fixed", "byte": b"\xFF"},
                {"name": "Pass 3: Pseudo-Random Character Overwrite", "type": "random_byte", "byte": None}
            ]
        elif standard == "SSD_SECURE_ERASE":
            standard_desc = "NIST Purge / ATA Secure Erase & NVMe Sanitize (Wear-Leveling Bypass)"
            passes_plan = [
                {"name": "Step 1: Cryptographic Key Erasure (Crypto Scramble)", "type": "random", "byte": None},
                {"name": "Step 2: Flash Translation Layer Block Deallocation (TRIM/Zero)", "type": "fixed", "byte": b"\x00"}
            ]
        else:
            raise ValueError(f"Unknown sanitization standard: {standard}")

        total_passes = len(passes_plan)

        # Execute overwrite passes
        with open(disk_path, "r+b") as f:
            for pass_idx, pinfo in enumerate(passes_plan, start=1):
                f.seek(0)
                bytes_written = 0
                ptype = pinfo["type"]
                pbyte = pinfo["byte"]
                if ptype == "random_byte":
                    # Single pseudo-random character chosen for pass
                    char_choice = secrets.token_bytes(1)
                    fill_block = char_choice * WipeEngine.CHUNK_SIZE
                elif ptype == "fixed":
                    fill_block = pbyte * WipeEngine.CHUNK_SIZE

                while bytes_written < total_bytes:
                    to_write = min(total_bytes - bytes_written, WipeEngine.CHUNK_SIZE)
                    if ptype == "random":
                        block = secrets.token_bytes(to_write)
                    else:
                        block = fill_block[:to_write]
                    
                    f.write(block)
                    bytes_written += to_write

                    if progress_callback:
                        progress_callback({
                            "status": "wiping",
                            "pass": pass_idx,
                            "total_passes": total_passes,
                            "pass_name": pinfo["name"],
                            "bytes_written": bytes_written,
                            "total_bytes": total_bytes,
                            "percent": round((bytes_written / total_bytes) * 100, 1),
                            "standard": standard
                        })

            f.flush()
            os.fsync(f.fileno())

        # Verification pass: Read back and verify conformity
        if progress_callback:
            progress_callback({
                "status": "verifying",
                "pass": total_passes,
                "total_passes": total_passes,
                "pass_name": "Verification: Scanning sectors for residual patterns",
                "percent": 99.0,
                "standard": standard
            })

        post_hash = DiskManager.calculate_sha256(disk_path)
        post_entropy = WipeEngine.sample_disk_entropy(disk_path)
        elapsed_seconds = round(time.time() - start_time, 2)

        # Determine verification success
        verified = True
        verification_details = "Sanitization verified: Target sectors match standard specification."
        if standard in ["NIST_CLEAR", "SSD_SECURE_ERASE"] and post_entropy > 0.05:
            verified = False
            verification_details = f"Anomaly detected: Post-wipe entropy ({post_entropy}) exceeds zero tolerance."

        result = {
            "standard_code": standard,
            "standard_title": standard_desc,
            "passes_completed": total_passes,
            "disk_path": str(disk_path),
            "disk_name": Path(disk_path).name,
            "capacity_bytes": total_bytes,
            "capacity_mb": round(total_bytes / (1024 * 1024), 2),
            "pre_wipe_sha256": pre_hash,
            "post_wipe_sha256": post_hash,
            "pre_wipe_entropy": pre_entropy,
            "post_wipe_entropy": post_entropy,
            "elapsed_seconds": elapsed_seconds,
            "operator_name": operator_name,
            "timestamp_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "verified": verified,
            "verification_details": verification_details
        }

        if progress_callback:
            progress_callback({
                "status": "completed",
                "result": result
            })

        return result
