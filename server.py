import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

# Add project root to path
ROOT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT_DIR))

from engine.disk_manager import DiskManager, SafetyException, DISKS_DIR
from engine.wipe_engine import WipeEngine
from engine.recovery_engine import RecoveryEngine, RECOVERED_DIR
from engine.certificate_generator import CertificateGenerator, CERTS_DIR
from engine.gemini_service import GeminiForensicService, PRESET_MYSTERY_ARTIFACTS
from engine.case_assistant import CaseAssistant


app = FastAPI(
    title="ForensiX Platform API",
    description="Certified Secure Data Sanitization & Forensic File Recovery API",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic Schemas
class CreateDiskRequest(BaseModel):
    filename: Optional[str] = "forensic_case_drive.img"
    size_mb: Optional[int] = 5

class WipeRequest(BaseModel):
    disk_path: str
    standard: str = "NIST_CLEAR"  # NIST_CLEAR, NIST_PURGE, DOD_5220_22_M, SSD_SECURE_ERASE
    operator_name: Optional[str] = "Forensic Examiner"

class CarveRequest(BaseModel):
    disk_path: str

class GeminiUnknownSearchRequest(BaseModel):
    query: Optional[str] = None
    hexSnippet: Optional[str] = None
    magicBytes: Optional[str] = None
    hash: Optional[str] = None
    fileExtension: Optional[str] = None
    context: Optional[str] = None
    searchMode: Optional[str] = "AUTO"

class GeminiCaseAssistantRequest(BaseModel):
    query: str
    caseRecord: Optional[Dict[str, Any]] = None
    artifactsSummary: Optional[Dict[str, Any]] = None
    antiForensicsSummary: Optional[List[Dict[str, Any]]] = None
    ledgerSummary: Optional[Dict[str, Any]] = None
    engineMode: Optional[str] = "GEMINI_3_7"

class ConfigureApiKeyRequest(BaseModel):
    apiKey: str


# Endpoints
@app.get("/api/status")
def get_status():
    return {
        "status": "online",
        "engine_version": "1.0.0",
        "standards_supported": [
            {"code": "NIST_CLEAR", "name": "NIST SP 800-88 Rev. 1 (Clear)", "passes": 1, "target": "HDD / Magnetic / Logical"},
            {"code": "NIST_PURGE", "name": "NIST SP 800-88 Rev. 1 (Purge)", "passes": 3, "target": "High Security / Cryptographic"},
            {"code": "DOD_5220_22_M", "name": "DoD 5220.22-M (3-Pass)", "passes": 3, "target": "Department of Defense Standard"},
            {"code": "SSD_SECURE_ERASE", "name": "ATA Secure Erase / NVMe Sanitize", "passes": 2, "target": "SSD / Flash (Wear-Leveling Bypass)"}
        ],
        "carver_signatures": ["JPEG", "PNG", "PDF", "ZIP/DOCX", "CREDENTIALS_TEXT"],
        "has_gemini_key": GeminiForensicService.has_api_key(),
        "gemini_model": "gemini-3.7-flash" if GeminiForensicService.has_api_key() else "gemini-3.7-flash (Embedded Knowledge Engine)"
    }

@app.get("/api/health")
def health_check():
    return {
        "status": "ok",
        "hasGeminiKey": GeminiForensicService.has_api_key(),
        "model": "gemini-3.7-flash",
        "engine": "ForensiX Certified Forensic Platform"
    }

@app.get("/api/gemini/status")
def get_gemini_status():
    return {
        "hasKey": GeminiForensicService.has_api_key(),
        "model": "gemini-3.7-flash",
        "groundingEnabled": GeminiForensicService.has_api_key(),
        "presetsCount": len(PRESET_MYSTERY_ARTIFACTS)
    }

@app.post("/api/gemini/configure")
def configure_gemini(req: ConfigureApiKeyRequest):
    GeminiForensicService.set_api_key(req.apiKey)
    return {
        "success": True,
        "hasKey": GeminiForensicService.has_api_key(),
        "message": "Gemini API key updated successfully."
    }

@app.get("/api/gemini/presets")
def get_gemini_presets():
    return {"presets": GeminiForensicService.get_presets()}

@app.post("/api/gemini/unknown-search")
def search_unknown_artifact(req: GeminiUnknownSearchRequest):
    try:
        if not GeminiForensicService.has_api_key():
            raise HTTPException(
                status_code=401,
                detail="GEMINI_API_KEY is not configured. Please add GEMINI_API_KEY to your Render environment variables or configure it in Studio settings."
            )
        if not req.query and not req.hexSnippet and not req.magicBytes and not req.hash:
            raise HTTPException(
                status_code=400,
                detail="At least one search parameter (query, hexSnippet, magicBytes, or hash) is required."
            )
        result = GeminiForensicService.search_unknown_artifact(
            query=req.query,
            hex_snippet=req.hexSnippet,
            magic_bytes=req.magicBytes,
            hash_val=req.hash,
            file_extension=req.fileExtension,
            context=req.context,
            search_mode=req.searchMode or "AUTO"
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/gemini/case-assistant")
def case_assistant_endpoint(req: GeminiCaseAssistantRequest):
    try:
        if not GeminiForensicService.has_api_key():
            raise HTTPException(
                status_code=401,
                detail="GEMINI_API_KEY is not configured. Please add GEMINI_API_KEY to your Render environment variables or configure it in Studio settings."
            )
        if not req.query.strip():
            raise HTTPException(status_code=400, detail="Query is required.")
        result = GeminiForensicService.query_case_assistant(
            query=req.query,
            case_record=req.caseRecord,
            artifacts_summary=req.artifactsSummary,
            anti_forensics_summary=req.antiForensicsSummary,
            ledger_summary=req.ledgerSummary,
            engine_mode=req.engineMode or "GEMINI_3_7"
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/api/disks")
def list_disks():
    try:
        disks = DiskManager.list_disks()
        return {"disks": disks}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/disks/create-sample")
def create_sample_disk(req: CreateDiskRequest):
    try:
        size_mb = max(2, min(req.size_mb or 5, 20))  # Bounds for fast safe demo
        result = DiskManager.create_sample_disk(req.filename or "forensic_demo.img", size_mb=size_mb)
        return {"success": True, "disk": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/hex-view")
def get_hex_view(disk_path: str, offset: int = 0, length: int = 256):
    try:
        return DiskManager.read_hex_window(disk_path, offset=offset, length=length)
    except SafetyException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/carve")
def carve_disk(req: CarveRequest):
    try:
        if not DiskManager.is_safe_target(req.disk_path):
            raise HTTPException(status_code=403, detail="Unsafe or invalid target disk path.")
        
        result = RecoveryEngine.carve_disk(req.disk_path)
        return {"success": True, "data": result}
    except SafetyException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/wipe")
def wipe_disk(req: WipeRequest):
    try:
        if not DiskManager.is_safe_target(req.disk_path):
            raise HTTPException(status_code=403, detail="Unsafe or invalid target disk path.")

        wipe_result = WipeEngine.execute_wipe(
            disk_path=req.disk_path,
            standard=req.standard,
            operator_name=req.operator_name or "Forensic Examiner"
        )
        # Automatically generate audit certificate
        cert_result = CertificateGenerator.generate_certificate(wipe_result)

        return {
            "success": True,
            "wipe_result": wipe_result,
            "certificate": cert_result
        }
    except SafetyException as e:
        raise HTTPException(status_code=403, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/certificates")
def list_certificates():
    certs = []
    for pdf_file in CERTS_DIR.glob("*.pdf"):
        stat = pdf_file.stat()
        cert_id = pdf_file.stem
        certs.append({
            "cert_id": cert_id,
            "filename": pdf_file.name,
            "size_bytes": stat.st_size,
            "created": stat.st_mtime,
            "download_url": f"/api/certificates/{cert_id}/download"
        })
    certs.sort(key=lambda x: x["created"], reverse=True)
    return {"certificates": certs}

@app.get("/api/certificates/{cert_id}/download")
def download_certificate(cert_id: str):
    pdf_path = CERTS_DIR / f"{cert_id}.pdf"
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Certificate not found.")
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=f"{cert_id}.pdf"
    )

@app.get("/api/recovered/{disk_stem}/{filename}")
def serve_recovered_file(disk_stem: str, filename: str):
    file_path = RECOVERED_DIR / disk_stem / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Recovered artifact not found.")
    return FileResponse(str(file_path))

# Mount static frontend
STATIC_DIR = ROOT_DIR / "static"
try:
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
except Exception:
    pass

@app.get("/studio")
@app.get("/app")
def serve_studio():
    studio_file = STATIC_DIR / "studio.html"
    if studio_file.exists():
        return FileResponse(str(studio_file))
    return FileResponse(str(STATIC_DIR / "index.html"))

app.mount("/", StaticFiles(directory=str(STATIC_DIR), html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8085))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"Starting ForensiX Platform on http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)

