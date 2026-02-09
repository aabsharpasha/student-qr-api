import os
import hmac
import hashlib
import json
import time
from typing import Optional, Tuple
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field
from datetime import datetime, timezone
from dotenv import load_dotenv
from fastapi.responses import StreamingResponse, HTMLResponse
from fastapi.templating import Jinja2Templates
import qrcode
import io

load_dotenv()
from supabase import create_client, Client
import httpx
import traceback

app = FastAPI(title="Student Attendance POC")

# Templates and class id for dashboard/rotating QR
templates = Jinja2Templates(directory="templates")
CLASS_ID = os.environ.get("CLASS_ID", "C101")

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)
QR_SECRET = os.environ.get("QR_SECRET", "change-me-in-production")
TEACHER_DIGIPIN = '39J-MC3-M77C'
QR_MAX_AGE_SECONDS = int(os.environ.get("QR_VALIDITY_SECONDS", "90"))
DIGIPIN_SERVICE_URL = os.environ.get("DIGIPIN_SERVICE_URL", "http://localhost:5000/api/digipin")

def sign_payload(payload: dict, secret: str) -> str:
    """Same as qrcodegen.py: HMAC-SHA256 of canonical JSON."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_secure_payload(class_data: dict, secret: str) -> dict:
    """Add timestamp and signature to payload (same behaviour as qrcodegen.py)."""
    payload = {**class_data, "ts": int(datetime.utcnow().timestamp())}
    sig = sign_payload(payload, secret)
    payload["sig"] = sig
    return payload


@app.post("/generate-qr")
async def generate_qr(class_data: dict):
    """Generate a signed QR (PNG) from provided class_data and return image bytes.

    Example `class_data` keys: `class_id`, `class_name`, `teacher`, `location`, `type`
    """
    payload = build_secure_payload(class_data, QR_SECRET)
    qr_string = json.dumps(payload)
    qr_obj = qrcode.QRCode(box_size=10, border=4)
    qr_obj.add_data(qr_string)
    qr_obj.make(fit=True)
    img = qr_obj.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


def _normalize_payload_for_signing(payload: dict) -> dict:
    """Ensure types match qrcodegen (e.g. ts as int) so canonical JSON is identical."""
    out = {}
    for k, v in payload.items():
        if k == "ts" and v is not None:
            out[k] = int(v)
        else:
            out[k] = v
    return out




async def get_digipin(lat: float, lon: float):
    async with httpx.AsyncClient() as client:
        # Encode: Lat/Long -> DIGIPIN
        response = await client.get(
            f"{DIGIPIN_SERVICE_URL}/encode", 
            params={"latitude": lat, "longitude": lon}
        )
        return response.json().get("digipin")



def verify_payload(data: dict, secret: str, max_age_seconds: int = QR_MAX_AGE_SECONDS) -> Tuple[bool, str]:
    """
    Same as qrcodegen.py: verify sig and ts.
    Returns (ok, detail_message).
    """
    if "sig" not in data or "ts" not in data:
        msg = "Missing sig or ts in QR payload."
        print("QR verify failed:", msg, data)
        return False, msg
    sig_received = data["sig"]
    payload = {k: v for k, v in data.items() if k != "sig"}
    payload = _normalize_payload_for_signing(payload)
    expected_sig = sign_payload(payload, secret)
    if not hmac.compare_digest(sig_received, expected_sig):
        msg = "Invalid QR signature or expired."
        print("QR verify failed:", msg, {"received": sig_received, "expected": expected_sig})
        return False, msg
    ts = payload["ts"]
    age = int(time.time()) - ts
    if age < 0:
        msg = "QR timestamp is in the future."
        print("QR verify failed:", msg, {"ts": ts, "now": int(time.time())})
        return False, msg
    if age > max_age_seconds:
        msg = "QR code expired. Ask teacher for a new one."
        print("QR verify failed:", msg, {"age": age, "max_age_seconds": max_age_seconds})
        return False, msg
    return True, ""


class AttendanceSchema(BaseModel):
    # Sample/default values aligned with the DB `attendance` table
    student_id: str = Field("student_123", description="Example non-null student_id")
    qr_payload: str = Field('{"sid":"C101","class_id":"C101","ts":1707400000,"sig":"sample-signature"}', description="Raw JSON string from the QR")
    # device_info stored as JSONB in DB
    device_info: Optional[dict] = Field(default_factory=lambda: {"id": "device-xyz"})
    # class_id is nullable in DB but provide a sample
    class_id: Optional[str] = "C101"
    # scanned_at: use timezone-aware datetime sample (DB default is now())
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    # student_digipin: varchar(12) nullable, provide sample 6-digit pin
    student_digipin: Optional[str] = ""
    # lat/long with sample precision matching numeric(9,6)
    student_lat: Optional[float] = 28.499532871022712
    student_long: Optional[float] = 77.18887154919041


@app.post("/check-in")
async def check_in(data: AttendanceSchema):
    
    # 1. Parse QR payload (app sends raw string from scanner)
    try:
        qr = json.loads(data.qr_payload)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid QR payload (not JSON)")

    # 2. Signature verification (must match qrcodegen.py; use same QR_SECRET when generating QRs)
    ok, detail = verify_payload(qr, QR_SECRET)
    if not ok:
        raise HTTPException(status_code=403, detail=detail)
    
    
    # compute DIGIPIN from lat/long when not provided explicitly
    student_digipin = data.student_digipin
    try:
        print(f"Generating DIGIPIN for lat={data.student_lat}, long={data.student_long}")
        if not student_digipin and data.student_lat is not None and data.student_long is not None:
           
            student_digipin = await get_digipin(float(data.student_lat), float(data.student_long))
            #print(student_digipin)
    except Exception as e:
        # if DIGIPIN generation fails, log the error for debugging and return a client error
        print("DIGIPIN generation error:", repr(e))
        print(traceback.format_exc())
        student_digipin = student_digipin
        raise HTTPException(status_code=400, detail="Student Location not able to generate DIGIPIN from lat/long")

    if student_digipin[:10] != TEACHER_DIGIPIN[:10]:
        raise HTTPException(status_code=403, detail="Student seems to be out of class not in range.")
    

    # determine class id from QR (prefer explicit class_id)
    class_id = qr.get("class_id") or qr.get("sid")

    # 2a. Check if student already checked in for this class on the same UTC day
    try:
        recent = (
            supabase.table("attendance")
            .select("scanned_at")
            .eq("student_id", data.student_id)
            .eq("class_id", class_id)
            .order("scanned_at", desc=True)
            .limit(1)
            .execute()
        )
    except Exception:
        recent = None

    recent_rows = []
    if recent is not None:
        # supabase client may return an object with a .data attr or a dict
        recent_rows = getattr(recent, "data", None) or (recent.get("data") if isinstance(recent, dict) else [])

    def _to_utc_date(dt: Optional[datetime]):
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).date()

    if recent_rows:
        scanned_at_raw = recent_rows[0].get("scanned_at")
        existing_dt = None
        if scanned_at_raw:
            try:
                existing_dt = datetime.fromisoformat(scanned_at_raw.replace("Z", "+00:00"))
            except Exception:
                existing_dt = None

        if existing_dt is not None:
            existing_date = _to_utc_date(existing_dt)
            current_date = _to_utc_date(data.scanned_at)
            if existing_date is not None and current_date is not None and existing_date == current_date:
                return {
                    "status": "already_checked",
                    "message": f"Student {data.student_id} already checked into {class_id} on {existing_date.isoformat()}",
                    "timestamp": int(time.time()),
                }

    # prepare row to insert; omit scanned_at so DB can default to now() when not provided
    row = {
        "student_id": data.student_id,
        "class_id": class_id,
        "device_info": data.device_info,
        "student_digipin": student_digipin,
        "student_lat": data.student_lat,
        "student_long": data.student_long,
        "scanned_at": data.scanned_at,
    }

    # convert datetime to ISO string so it's JSON serializable for the client
    if isinstance(row.get("scanned_at"), datetime):
        row["scanned_at"] = row["scanned_at"].isoformat()

    # remove keys with None so DB defaults apply
    row = {k: v for k, v in row.items() if v is not None}

    response = supabase.table("attendance").insert(row).execute()


    # 3. Success
    print(f"Verified Attendance: {data.student_id} in Class {class_id}")
    return {
        "status": "success",
        "message": f"Checked into {class_id}",
        "timestamp": int(time.time()),
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "class_id": CLASS_ID})


@app.get("/qr-code")
async def get_qr():
    # Rotate QR every 30s
    ts = int(time.time() / 30) * 30
    payload = {"sid": CLASS_ID, "ts": ts}
    payload["sig"] = sign_payload(payload, QR_SECRET)
    
    qr_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    img = qrcode.make(qr_str)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


@app.get("/api/attendance")
async def list_attendance(limit: int = 100, class_id: Optional[str] = None):
    """Return recent attendance rows as JSON, filtered by class_id (defaults to CLASS_ID)."""
    cid = class_id or CLASS_ID
    try:
        resp = (
            supabase.table("attendance")
            .select("id, student_id, class_id, student_digipin, student_lat, student_long, scanned_at")
            .eq("class_id", cid)
            .order("scanned_at", desc=True)
            .limit(limit)
            .execute()
        )
    except Exception:
        return []

    rows = getattr(resp, "data", None) or (resp.get("data") if isinstance(resp, dict) else [])
    return rows

# Structure: { "STU_001": "DEVICE_SERIAL_XYZ" }
device_registry = {}

@app.post("/bind-device")
async def bind_device(student_id: str, device_id: str):
    # 1. Check if this student ID is already taken by another device
    if student_id in device_registry:
        if device_registry[student_id] != device_id:
            raise HTTPException(
                status_code=403, 
                detail="This Student ID is already registered on another device."
            )
        return {"status": "already_bound", "message": "Welcome back!"}
    
    # 2. Lock the ID to this device
    device_registry[student_id] = device_id
    return {"status": "success", "message": f"Bound to {student_id}"}