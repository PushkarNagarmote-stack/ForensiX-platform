import os
import sys
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from engine.disk_manager import DiskManager
from engine.wipe_engine import WipeEngine
from engine.recovery_engine import RecoveryEngine
from engine.certificate_generator import CertificateGenerator

def test_full_pipeline():
    print("\n" + "="*70)
    print("  FORENSIX COMPREHENSIVE SUITE - AUTOMATED PIPELINE TEST")
    print("="*70)

    # 1. Create Virtual Test Disk
    print("\n[*] Step 1: Creating 5MB synthetic forensic test disk...")
    disk_info = DiskManager.create_sample_disk("test_evidence_drive.img", size_mb=5)
    print(f"    [+] Created: {disk_info['name']}")
    print(f"    [+] Size: {disk_info['size_mb']} MB ({disk_info['size_bytes']} bytes)")
    print(f"    [+] Initial SHA-256: {disk_info['sha256']}")
    print(f"    [+] Injected Evidence Files: {len(disk_info['injected_files'])}")
    for f in disk_info['injected_files']:
        print(f"        -> {f['filename']} at Sector {f['sector']} ({f['size_bytes']} bytes)")

    # 2. Test Hex Window Reader
    print("\n[*] Step 2: Testing raw hex sector inspection...")
    hex_view = DiskManager.read_hex_window(disk_info['path'], offset=0, length=64)
    print(f"    [+] Read {len(hex_view['rows'])} rows from offset {hex_view['offset']}:")
    for r in hex_view['rows']:
        print(f"        {r['offset']}  {r['hex']}  |{r['ascii']}|")

    # 3. Test Deep File Carving (Pre-Wipe)
    print("\n[*] Step 3: Executing deep signature carving before wipe...")
    carve_results = RecoveryEngine.carve_disk(disk_info['path'])
    print(f"    [+] Total Sectors Scanned: {carve_results['sectors_scanned']}")
    print(f"    [+] Recovered Artifacts: {carve_results['total_recovered']}")
    assert carve_results['total_recovered'] >= 4, "Expected at least 4 files recovered!"
    for r in carve_results['recovered_files']:
        print(f"        [CARVED] #{r['id']} {r['filename']} ({r['file_type']}) - Size: {r['size_kb']} KB, Conf: {r['confidence_percent']}%, Status: {r['status']}")

    # 4. Test NIST SP 800-88 Rev. 1 Clear Wipe
    print("\n[*] Step 4: Executing NIST SP 800-88 Rev. 1 (Clear) sanitization...")
    wipe_result = WipeEngine.execute_wipe(
        disk_path=disk_info['path'],
        standard="NIST_CLEAR",
        operator_name="Inspector Pushkar (SIH Core)"
    )
    print(f"    [+] Standard: {wipe_result['standard_title']}")
    print(f"    [+] Pre-Wipe Entropy:  {wipe_result['pre_wipe_entropy']:.4f} bits/byte")
    print(f"    [+] Post-Wipe Entropy: {wipe_result['post_wipe_entropy']:.4f} bits/byte")
    print(f"    [+] Pre-Wipe SHA-256:  {wipe_result['pre_wipe_sha256']}")
    print(f"    [+] Post-Wipe SHA-256: {wipe_result['post_wipe_sha256']}")
    print(f"    [+] Verification Passed: {wipe_result['verified']} ({wipe_result['verification_details']})")
    assert wipe_result['verified'] is True, "Wipe verification should succeed!"
    assert wipe_result['post_wipe_entropy'] == 0.0, "Post-wipe entropy should be 0.0 for zero fill!"

    # 5. Test Post-Wipe Recovery (Should find 0 files!)
    print("\n[*] Step 5: Validating that carved files can NO LONGER be recovered post-wipe...")
    post_carve = RecoveryEngine.carve_disk(disk_info['path'])
    print(f"    [+] Post-wipe files recovered: {post_carve['total_recovered']}")
    assert post_carve['total_recovered'] == 0, "Post-wipe carve MUST return 0 files!"
    print("    [+] PROVEN: Zero recoverable artifacts remain. 100% forensic sanitization!")

    # 6. Test PDF Certificate Generation
    print("\n[*] Step 6: Generating official ReportLab PDF Sanitization Certificate...")
    cert_info = CertificateGenerator.generate_certificate(wipe_result)
    print(f"    [+] Certificate Generated: {cert_info['cert_id']}")
    print(f"    [+] File Path: {cert_info['path']}")
    cert_size = os.path.getsize(cert_info['path'])
    print(f"    [+] PDF File Size: {cert_size:,} bytes")
    assert cert_size > 1000, "Certificate PDF should be populated!"

    print("\n" + "="*70)
    print("  ALL FORENSIC PIPELINE TESTS PASSED WITH 100% SUCCESS!")
    print("="*70 + "\n")

if __name__ == "__main__":
    test_full_pipeline()
