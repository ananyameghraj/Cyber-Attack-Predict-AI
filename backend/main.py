import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI(title="CyberPredict AI API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://.*",
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": f"Server processing error: {str(exc)}"},
    )


STAGES = [
    "Normal Traffic",
    "Port Scanning",
    "Suspicious Login",
    "Privilege Escalation",
    "Data Exfiltration",
]

DATA_DIR = (Path(__file__).resolve().parent / "data") if (Path(__file__).resolve().parent / "data").exists() else (Path(__file__).resolve().parent.parent / "data")
ALLOWED_DATASET_SUFFIXES = {".csv", ".json", ".jsonl"}

def _normalize(value: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).strip().lower()).strip("_")

def _number(row: dict[str, Any], names: tuple[str, ...]) -> float:
    normalized_names = {_normalize(name) for name in names}
    for key, value in row.items():
        if _normalize(key) in normalized_names:
            try:
                return float(value)
            except (TypeError, ValueError):
                pass
    return 0.0

def _numeric_total(rows: list[dict[str, Any]], excluded: set[str]) -> float:
    total = 0.0
    for row in rows:
        for key, value in row.items():
            if _normalize(key) in excluded:
                continue
            try:
                number = float(value)
                if number == number:
                    total += number
            except (TypeError, ValueError):
                continue
    return total

def _dataset_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    populated_rows = [row for row in rows if any(str(value or "").strip() for value in row.values())]
    if not populated_rows:
        raise ValueError("The dataset contains headers but no populated data rows.")
    rows = populated_rows
    row_count = len(rows)
    failed_logins = sum(_number(row, ("failed_logins", "failed_login_attempts", "login_failures", "login_attempts")) for row in rows)
    traffic = sum(_number(row, ("traffic_volume", "bytes", "network_packet_size", "network_traffic", "traffic")) for row in rows)
    if traffic == 0:
        traffic = _numeric_total(rows, {"id", "session_id", "org_id", "incident_id", "alert_id"})
    stages_found = [" ".join(str(value or "") for value in row.values()).lower() for row in rows]
    stage_index = 0
    stage_keywords = {
        4: ("exfil", "data theft", "outbound transfer"),
        3: ("privilege", "escalat", "admin", "root"),
        2: ("login", "credential", "account", "authentication"),
        1: ("scan", "port", "probe", "recon"),
    }
    for index, keywords in stage_keywords.items():
        if any(any(keyword in value for keyword in keywords) for value in stages_found):
            stage_index = max(stage_index, index)
    threat_score = min(99, round((failed_logins * 2 + stage_index * 18 + min(row_count, 100) / 4)))
    confidence = min(98, max(54, 64 + stage_index * 6 + min(row_count, 40) // 4))
    source_keys = ("source_ip", "src_ip", "source", "device_id")
    sources = {str(row.get(key)) for row in rows for key in source_keys if row.get(key)}
    if not sources:
        sources = {str(row.get(key)) for row in rows for key in row if any(token in _normalize(key) for token in ("ip", "device", "org", "detector")) and row.get(key)}
    return {
        "row_count": row_count,
        "source_count": len(sources),
        "failed_logins": round(failed_logins),
        "traffic": round(traffic, 2),
        "threat_score": threat_score,
        "confidence": confidence,
        "current_stage": STAGES[stage_index],
        "predicted_next_stage": STAGES[min(stage_index + 1, len(STAGES) - 1)],
        "risk": "CRITICAL" if threat_score >= 75 else "HIGH" if threat_score >= 45 else "ELEVATED",
    }

class ForecastRequest(BaseModel):
    events: list[dict[str, Any]] = []
    current_stage: str = "Suspicious Login"

@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "cyberpredict-api", "mode": "demo"}

@app.post("/api/dataset")
async def upload_dataset(file: UploadFile = File(...)) -> dict[str, Any]:
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_DATASET_SUFFIXES:
        raise HTTPException(status_code=400, detail="Only CSV, JSON, and JSONL datasets are supported.")
    safe_name = Path(file.filename or "dataset" + suffix).name
    DATA_DIR.mkdir(exist_ok=True)
    destination = DATA_DIR / safe_name
    contents = await file.read()
    destination.write_bytes(contents)
    try:
        if suffix == ".csv":
            rows = list(csv.DictReader(io.StringIO(contents.decode("utf-8-sig"))))
        elif suffix == ".jsonl":
            rows = [json.loads(line) for line in contents.decode("utf-8").splitlines() if line.strip()]
        else:
            parsed = json.loads(contents.decode("utf-8"))
            rows = parsed if isinstance(parsed, list) else parsed.get("data", [parsed])
        rows = [row for row in rows if isinstance(row, dict)]
    except (UnicodeDecodeError, json.JSONDecodeError, AttributeError) as error:
        raise HTTPException(status_code=400, detail=f"Could not parse dataset: {error}") from error
    try:
        summary = _dataset_summary(rows)
    except ValueError as error:
        raise HTTPException(status_code=400, detail=str(error)) from error
    return {"filename": safe_name, "path": f"data/{safe_name}", "summary": summary, "simulated": True}

@app.post("/api/forecast")
def forecast(payload: ForecastRequest) -> dict[str, Any]:
    try:
        current_index = STAGES.index(payload.current_stage)
    except ValueError:
        current_index = 2
    next_index = min(current_index + 1, len(STAGES) - 1)
    confidence = min(98, 78 + current_index * 5)
    return {
        "current_stage": STAGES[current_index],
        "predicted_next_stage": STAGES[next_index],
        "risk": "CRITICAL" if current_index >= 3 else "HIGH",
        "confidence": confidence,
        "simulated": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

@app.post("/api/simulate")
def simulate() -> dict[str, Any]:
    return {
        "stages": STAGES,
        "interval_ms": 1500,
        "simulated": True,
        "message": "Demo attack sequence generated. No trained ML model was queried.",
    }
