import os
import hmac
import hashlib
import json
import time
import tempfile
from collections import Counter
from typing import Optional, Tuple, Union
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from datetime import datetime, timezone, timedelta

try:
    from zoneinfo import ZoneInfo
    IST = ZoneInfo("Asia/Kolkata")
except ImportError:
    IST = timezone(timedelta(hours=5, minutes=30))  # Asia/Kolkata = UTC+5:30
from dotenv import load_dotenv
from fastapi.responses import StreamingResponse, HTMLResponse, FileResponse
from fastapi.templating import Jinja2Templates
import qrcode
import io
import base64
import uuid
from pathlib import Path

load_dotenv()
from supabase import create_client, Client
import httpx
import traceback

app = FastAPI(title="Student Attendance POC")

@app.get("/health")
def health():
    return {"status": "ok"}
# Templates and class id for dashboard/rotating QR
templates = Jinja2Templates(directory="templates")
CLASS_ID = os.environ.get("CLASS_ID", "C101")

url: str = os.environ.get("SUPABASE_URL")
key: str = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(url, key)
QR_SECRET = os.environ.get("QR_SECRET", "change-me-in-production")
TEACHER_DIGIPIN = '39J-MC3-M77C'
QR_MAX_AGE_SECONDS = int(os.environ.get("QR_VALIDITY_SECONDS", "90"))  # 30s refresh + 60s buffer
# Within this many seconds, duplicate check-in is rejected; after this, new row is allowed
DUPLICATE_WINDOW_SECONDS = int(os.environ.get("DUPLICATE_WINDOW_SECONDS", "120"))  # 2 minutes
DIGIPIN_SERVICE_URL = os.environ.get("DIGIPIN_SERVICE_URL", "http://localhost:5000/api/digipin")

session_context = {
    "teacher_digipin": None,  # Default starting value
    "is_active": True
}

@app.get("/session/setup")
async def setup_session(digipin: str):
    """Update the teacher's location for the current demo run"""
    session_context["teacher_digipin"] = digipin
    return {"message": f"Classroom location set to {digipin}"}

def sign_payload(payload: dict, secret: str) -> str:
    """Same as qrcodegen.py: HMAC-SHA256 of canonical JSON."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(
        secret.encode("utf-8"),
        canonical.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def build_secure_payload(class_data: dict, secret: str) -> dict:
    """Add timestamp and signature to payload (IST-aligned with phone)."""
    payload = {**class_data, "ts": int(datetime.now(IST).timestamp())}
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
    # device_info stored as JSONB in DB (app may send device_id instead)
    device_info: Optional[dict] = None
    # class_id is nullable in DB but provide a sample
    class_id: Optional[str] = "C101"
    # scanned_at: use timezone-aware datetime (app may send Unix timestamp)
    scanned_at: Optional[Union[datetime, int, str]] = None
    # student_digipin: varchar(12) nullable
    student_digipin: Optional[str] = ""
    # lat/long (app may send lat/lng instead of student_lat/student_long)
    student_lat: Optional[float] = None
    student_long: Optional[float] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    device_id: Optional[str] = None
    # photo_matched: when False, mark attendance as suspicious
    photo_matched: Optional[bool] = None
    # suspicious_reason: why marked suspicious (e.g. "Photo mismatch")
    suspicious_reason: Optional[str] = None

    @field_validator("scanned_at", mode="before")
    @classmethod
    def parse_scanned_at(cls, v):
        if v is None:
            return datetime.now(IST)
        if isinstance(v, int):
            return datetime.fromtimestamp(v, tz=IST)
        if isinstance(v, str) and v.replace(".", "").isdigit():
            return datetime.fromtimestamp(int(float(v)), tz=IST)
        return v


def _log(step: str, msg: str, **kwargs):
    print(f"[ATTENDANCE] {step}: {msg}", kwargs or "")


@app.post("/check-in")
async def check_in(data: AttendanceSchema):
    _log("CHECK_IN", "Request received", student_id=data.student_id, has_qr=bool(data.qr_payload))

    # 1. Parse QR payload (app sends raw string from scanner)
    try:
        qr = json.loads(data.qr_payload)
        _log("CHECK_IN", "QR parsed", qr_keys=list(qr.keys()))
    except json.JSONDecodeError:
        _log("CHECK_IN", "QR parse failed - invalid JSON")
        raise HTTPException(status_code=400, detail="Invalid QR payload (not JSON)")

    # 2. Signature verification
    ok, detail = verify_payload(qr, QR_SECRET)
    _log("CHECK_IN", "QR signature verified" if ok else "QR verification failed", ok=ok, detail=detail)
    if not ok:
        raise HTTPException(status_code=403, detail=detail)

    # Map app fields (lat/lng/device_id) to schema fields
    student_lat = data.student_lat if data.student_lat is not None else data.lat
    student_long = data.student_long if data.student_long is not None else data.lng
    device_info = data.device_info if data.device_info else ({"id": data.device_id} if data.device_id else {"id": "unknown"})
    scanned_at = data.scanned_at if data.scanned_at else datetime.now(IST)
    suspicious = not data.photo_matched if data.photo_matched is not None and data.photo_matched is False else False
    # Store "Face verification failed" for photo mismatch (do not save similarity message from match-photo)
    suspicious_reason = "Face verification failed" if (suspicious and data.photo_matched is False) else (data.suspicious_reason if data.suspicious_reason else None)
    _log("CHECK_IN", "Mapped fields", student_lat=student_lat, student_long=student_long, suspicious=suspicious, suspicious_reason=suspicious_reason)

    # compute DIGIPIN from lat/long when not provided explicitly
    student_digipin = data.student_digipin
    try:
        _log("CHECK_IN", "Generating DIGIPIN", lat=student_lat, long=student_long)
        if not student_digipin and student_lat is not None and student_long is not None:
            student_digipin = await get_digipin(float(student_lat), float(student_long))
            #print(student_digipin)
    except Exception as e:
        # if DIGIPIN generation fails, log the error for debugging and return a client error
        print("DIGIPIN generation error:", repr(e))
        print(traceback.format_exc())
        student_digipin = student_digipin
        raise HTTPException(status_code=400, detail="Student Location not able to generate DIGIPIN from lat/long")
    teacher_digipin_id = session_context.get("teacher_digipin") or TEACHER_DIGIPIN
    _log("CHECK_IN", "DIGIPIN", student_digipin=student_digipin, teacher_digipin=teacher_digipin_id)
    if student_digipin and len(teacher_digipin_id) >= 10 and student_digipin[:10] != teacher_digipin_id[:10]:
        _log("CHECK_IN", "DIGIPIN mismatch - student outside class", student_prefix=student_digipin[:10], teacher_prefix=teacher_digipin_id[:10])
        raise HTTPException(status_code=403, detail="Student seems to be outside class.")
    

    class_id = qr.get("class_id") or qr.get("sid")
    _log("CHECK_IN", "Class ID", class_id=class_id)

    # 2a. Duplicate check (within 2 min)
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
        recent_rows = getattr(recent, "data", None) or (recent.get("data") if isinstance(recent, dict) else [])

    if recent_rows:
        scanned_at_raw = recent_rows[0].get("scanned_at")
        existing_dt = None
        if scanned_at_raw:
            try:
                existing_dt = datetime.fromisoformat(scanned_at_raw.replace("Z", "+00:00"))
            except Exception:
                existing_dt = None

        if existing_dt is not None:
            existing_ts = existing_dt.timestamp()
            current_ts = scanned_at.timestamp() if isinstance(scanned_at, datetime) else time.time()
            age_seconds = current_ts - existing_ts
            _log("CHECK_IN", "Duplicate check", age_seconds=age_seconds, window=DUPLICATE_WINDOW_SECONDS, is_duplicate=(0 <= age_seconds < DUPLICATE_WINDOW_SECONDS))
            if 0 <= age_seconds < DUPLICATE_WINDOW_SECONDS:
                # Convert to Indian time for display (DB stores UTC)
                if existing_dt.tzinfo is None:
                    existing_dt = existing_dt.replace(tzinfo=timezone.utc)
                existing_ist = existing_dt.astimezone(IST)
                db_time_str = existing_ist.strftime("%Y-%m-%d %H:%M:%S IST")
                return {
                    "status": "already_checked",
                    "message": f"Attendance already marked at {db_time_str}.",
                    "scanned_at": existing_dt.isoformat(),
                    "timestamp": int(time.time()),
                }

    # prepare row to insert; include suspicious and reason when photo did not match
    row = {
        "student_id": data.student_id,
        "class_id": class_id,
        "device_info": device_info,
        "student_digipin": student_digipin,
        "student_lat": student_lat,
        "student_long": student_long,
        "scanned_at": scanned_at,
        "suspicious": suspicious,
        "suspicious_reason": suspicious_reason,
    }

    # convert datetime to ISO string so it's JSON serializable for the client
    if isinstance(row.get("scanned_at"), datetime):
        row["scanned_at"] = row["scanned_at"].isoformat()

    # remove keys with None so DB defaults apply
    row = {k: v for k, v in row.items() if v is not None}
    _log("CHECK_IN", "Inserting row", row_keys=list(row.keys()), suspicious=row.get("suspicious"))

    response = supabase.table("attendance").insert(row).execute()

    _log("CHECK_IN", "Success", student_id=data.student_id, class_id=class_id)
    return {
        "status": "success",
        "message": f"Checked into {class_id}",
        "timestamp": int(time.time()),
    }


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request, "class_id": CLASS_ID})


@app.get("/reference-photo/{student_id}")
async def get_reference_photo(student_id: str):
    """Serve the reference photo for a student (used for side-by-side display in app)."""
    ref_path = _get_reference_photo_path(student_id)
    if not ref_path or not ref_path.exists():
        raise HTTPException(status_code=404, detail="Reference photo not found")
    media = "image/jpeg" if ref_path.suffix.lower() in (".jpg", ".jpeg") else "image/png"
    return FileResponse(ref_path, media_type=media)


def _get_reference_photo_path(student_id: str) -> Optional[Path]:
    """Return path to reference photo for student, or None if not found."""
    ref_dir = Path("photos") / "reference"
    for ext in (".jpg", ".jpeg", ".png"):
        p = ref_dir / f"{student_id}{ext}"
        if p.exists():
            return p
    return None


# POC: 60% similarity threshold for photo match (perceptual hash)
PHOTO_MATCH_THRESHOLD = 0.60


def _crop_face_if_detected(cv_img):
    """Extract face region if detected; else return full image."""
    try:
        import cv2
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        cascade = cv2.CascadeClassifier(
            cv2.data.haarcascades + "haarcascade_frontalface_default.xml"
        )
        faces = cascade.detectMultiScale(gray, 1.1, 4, minSize=(80, 80))
        if len(faces) > 0:
            x, y, w, h = max(faces, key=lambda f: f[2] * f[3])
            pad = int(max(w, h) * 0.2)
            h_img, w_img = cv_img.shape[:2]
            x1 = max(0, x - pad)
            y1 = max(0, y - pad)
            x2 = min(w_img, x + w + pad)
            y2 = min(h_img, y + h + pad)
            return cv_img[y1:y2, x1:x2]
    except Exception:
        pass
    return cv_img


def _photo_similarity(ref_img, scan_img) -> float:
    """Return similarity 0–1 using perceptual hash. >= 0.7 = match for POC."""
    try:
        import cv2
        import imagehash
        from PIL import Image

        def _cv_to_pil(cv_img):
            rgb = cv2.cvtColor(cv_img, cv2.COLOR_BGR2RGB)
            return Image.fromarray(rgb)

        ref_pil = _cv_to_pil(ref_img)
        scan_pil = _cv_to_pil(scan_img)
        h1 = imagehash.phash(ref_pil, hash_size=16)
        h2 = imagehash.phash(scan_pil, hash_size=16)
        dist = h1 - h2
        max_dist = 256
        similarity = 1.0 - (dist / max_dist)
        return float(max(0.0, min(1.0, similarity)))
    except Exception as e:
        print("_photo_similarity error:", repr(e), traceback.format_exc())
        return 0.0


@app.post("/match-photo")
async def match_photo(payload: dict):
    student_id = payload.get("student_id")
    photo_b64 = payload.get("photo_base64")
    print("[ATTENDANCE] MATCH_PHOTO: Request received", {"student_id": student_id, "photo_len": len(photo_b64) if photo_b64 else 0})
    if not student_id:
        raise HTTPException(status_code=400, detail="Missing student_id")
    if not photo_b64:
        raise HTTPException(status_code=400, detail="Missing photo_base64")

    if isinstance(photo_b64, str) and photo_b64.startswith("data:"):
        try:
            photo_b64 = photo_b64.split(",", 1)[1]
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid data URI for photo_base64")

    try:
        img_bytes = base64.b64decode(photo_b64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 for photo_base64")

    ref_path = _get_reference_photo_path(student_id)
    print("[ATTENDANCE] MATCH_PHOTO: Reference path", {"ref_path": str(ref_path) if ref_path else None})
    if not ref_path:
        return {
            "matched": False,
            "message": f"No reference photo on file for {student_id}. Add one to photos/reference/{student_id}.jpg",
            "student_id": student_id,
        }

    try:
        import cv2
        import numpy as np

        ref_cv = cv2.imread(str(ref_path))
        if ref_cv is None:
            return {
                "matched": False,
                "message": "Could not load reference photo",
                "student_id": student_id,
            }

        npy = np.frombuffer(img_bytes, np.uint8)
        scan_cv = cv2.imdecode(npy, cv2.IMREAD_COLOR)
        if scan_cv is None:
            return {
                "matched": False,
                "message": "Invalid image data",
                "student_id": student_id,
            }

        ref_face = _crop_face_if_detected(ref_cv)
        scan_face = _crop_face_if_detected(scan_cv)
        print("[ATTENDANCE] MATCH_PHOTO: Face crop", {"ref_shape": ref_face.shape, "scan_shape": scan_face.shape})

        similarity = _photo_similarity(ref_face, scan_face)
        matched = similarity >= PHOTO_MATCH_THRESHOLD
        print("[ATTENDANCE] MATCH_PHOTO: Result", {"similarity": float(similarity), "threshold": PHOTO_MATCH_THRESHOLD, "matched": bool(matched)})

        return {
            "matched": bool(matched),
            "score": float(round(similarity, 2)),
            "student_id": student_id,
            "message": f"Match {similarity:.0%}" if matched else f"Similarity {similarity:.0%} (need {PHOTO_MATCH_THRESHOLD:.0%})",
        }
    except Exception as e:
        print("match-photo error:", repr(e), traceback.format_exc())
        return {
            "matched": False,
            "message": str(e),
            "student_id": student_id,
        }


@app.get("/qr-code")
async def get_qr():
    # Rotate QR every 30s (IST-aligned with phone)
    ts = int(datetime.now(IST).timestamp() / 30) * 30
    payload = {"sid": CLASS_ID, "ts": ts}
    payload["sig"] = sign_payload(payload, QR_SECRET)
    
    qr_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    img = qrcode.make(qr_str)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")


def _get_modal_digipin_prefix(rows: list, prefix_len: int = 10) -> Optional[str]:
    """Return the most common DIGIPIN prefix among rows (first prefix_len chars)."""
    prefixes = []
    for r in rows:
        d = r.get("student_digipin") or ""
        if d and len(d) >= prefix_len:
            prefixes.append(d[:prefix_len])
    if not prefixes:
        return None
    return Counter(prefixes).most_common(1)[0][0]


def _apply_digipin_clustering(rows: list) -> list:
    """Mark attendance as suspicious if DIGIPIN doesn't cluster with other students."""
    if len(rows) < 2:
        return rows
    modal_prefix = _get_modal_digipin_prefix(rows)
    if not modal_prefix:
        return rows
    for r in rows:
        d = r.get("student_digipin") or ""
        if not d or len(d) < len(modal_prefix):
            continue
        if d[:len(modal_prefix)] != modal_prefix:
            r["suspicious"] = True
            existing = (r.get("suspicious_reason") or "").strip()
            reason = "Student seems to be outside class. It's locaiton not matching with other students."
            r["suspicious_reason"] = f"{existing}; {reason}".strip("; ").strip() if existing else reason
    return rows


@app.get("/api/attendance")
async def list_attendance(limit: int = 100, class_id: Optional[str] = None):
    """Return recent attendance rows as JSON, filtered by class_id (defaults to CLASS_ID).
    Marks records as suspicious if DIGIPIN doesn't cluster with other students."""
    cid = class_id or CLASS_ID
    try:
        resp = (
            supabase.table("attendance")
            .select("id, student_id, class_id, student_digipin, student_lat, student_long, scanned_at, suspicious, suspicious_reason")
            .eq("class_id", cid)
            .order("scanned_at", desc=True)
            .limit(limit)
            .execute()
        )
    except Exception:
        return []

    rows = getattr(resp, "data", None) or (resp.get("data") if isinstance(resp, dict) else [])
    return _apply_digipin_clustering(rows)

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