# import io
# import os
# import uuid
# import json
# import logging
# from logging.handlers import RotatingFileHandler
# from datetime import datetime, timedelta

# from fastapi import FastAPI, UploadFile, File, HTTPException, Depends, Request
# from fastapi.security import HTTPBearer
# from pydantic import BaseModel
# from redis import Redis
# from minio import Minio
# import jwt

# # ----------------------
# # Logging configuration
# # ----------------------
# LOG_DIR = "/var/log/mvp-scanner"
# LOG_FILE = os.path.join(LOG_DIR, "submission.log")
# LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# logger = logging.getLogger("submission")
# logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))

# # File handler (rotating)
# fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
# fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
# logger.addHandler(fh)

# # Console handler
# ch = logging.StreamHandler()
# ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
# logger.addHandler(ch)

# # ----------------------
# # App & config
# # ----------------------
# app = FastAPI(title="MVP Scanner - Submission API")

# security = HTTPBearer()
# JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret")
# JWT_ALG = "HS256"

# BASIC_USER = os.getenv("BASIC_USER")
# BASIC_PASS = os.getenv("BASIC_PASS")

# redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# redis = Redis.from_url(redis_url, decode_responses=True)

# minio_endpoint = os.getenv("MINIO_ENDPOINT", "localhost:9000")
# minio_access_key = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
# minio_secret_key = os.getenv("MINIO_SECRET_KEY", "minioadmin")
# minio_bucket = os.getenv("MINIO_BUCKET", "uploads")

# minio_client = Minio(
#     minio_endpoint,
#     access_key=minio_access_key,
#     secret_key=minio_secret_key,
#     secure=False,
# )

# # Create bucket if needed
# if not minio_client.bucket_exists(minio_bucket):
#     minio_client.make_bucket(minio_bucket)
#     logger.info("Created MinIO bucket '%s'", minio_bucket)

# # ----------------------
# # Models
# # ----------------------
# class SubmitResponse(BaseModel):
#     message: str
#     file_id: str

# class TokenRequest(BaseModel):
#     username: str
#     password: str

# class TokenResponse(BaseModel):
#     access_token: str
#     token_type: str = "bearer"

# # ----------------------
# # Auth helpers
# # ----------------------
# def create_access_token(sub: str, expires_minutes: int = 60) -> str:
#     payload = {
#         "sub": sub,
#         "iat": datetime.utcnow(),
#         "exp": datetime.utcnow() + timedelta(minutes=expires_minutes),
#     }
#     return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

# def verify_token(credentials=Depends(security)):
#     token = credentials.credentials
#     try:
#         payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
#         return payload
#     except jwt.ExpiredSignatureError:
#         raise HTTPException(status_code=401, detail="Token expired")
#     except jwt.InvalidTokenError:
#         raise HTTPException(status_code=401, detail="Invalid token")

# # ----------------------
# # Middleware
# # ----------------------
# @app.middleware("http")
# async def log_requests(request: Request, call_next):
#     logger.info("REQ %s %s", request.method, request.url.path)
#     response = await call_next(request)
#     logger.info("RES %s %s -> %s", request.method, request.url.path, response.status_code)
#     return response

# # ----------------------
# # Routes
# # ----------------------
# @app.post("/auth/token", response_model=TokenResponse, tags=["auth"])
# def issue_token(body: TokenRequest):
#     if BASIC_USER and BASIC_PASS:
#         if body.username != BASIC_USER or body.password != BASIC_PASS:
#             logger.warning("Invalid auth attempt for user '%s'", body.username)
#             raise HTTPException(status_code=401, detail="Invalid credentials")
#     # If BASIC_* not set, allow any user (dev-mode)
#     token = create_access_token(sub=body.username)
#     logger.info("Issued token for '%s'", body.username)
#     return TokenResponse(access_token=token)

# @app.post("/submit", response_model=SubmitResponse, tags=["scan"])
# async def submit(file: UploadFile = File(...), user=Depends(verify_token)):
#     try:
#         contents = await file.read()
#         data_stream = io.BytesIO(contents)
#         file_id = str(uuid.uuid4())
#         minio_client.put_object(
#             minio_bucket,
#             file_id,
#             data=data_stream,
#             length=len(contents),
#             content_type=file.content_type or "application/octet-stream",
#         )
#         # Queue task in Redis
#         job = {"file_id": file_id, "filename": file.filename}
#         redis.lpush("jobs", json.dumps(job))
#         logger.info("Enqueued job file_id=%s name=%s size=%d", file_id, file.filename, len(contents))
#         return SubmitResponse(message="File submitted successfully", file_id=file_id)
#     except Exception as e:
#         logger.exception("Submit failed: %s", e)
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/report/{file_id}", tags=["scan"])
# def get_report(file_id: str, user=Depends(verify_token)):
#     try:
#         report_data = redis.get(f"report:{file_id}")
#         if report_data:
#             logger.info("Report fetched file_id=%s", file_id)
#             return {"file_id": file_id, "report": json.loads(report_data)}
#         else:
#             logger.info("Report not ready file_id=%s", file_id)
#             return {"file_id": file_id, "report": None, "message": "Report not found yet"}
#     except Exception as e:
#         logger.exception("Report retrieval failed for %s: %s", file_id, e)
#         raise HTTPException(status_code=500, detail=str(e))

import os
import json
import jwt
import redis
import uuid
from datetime import datetime, timedelta

from fastapi import FastAPI, File, UploadFile, HTTPException, Depends, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, HttpUrl
from minio import Minio

# -------------------- Config --------------------
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
REDIS_DB = int(os.getenv("REDIS_DB", 0))
REDIS_QUEUE = os.getenv("REDIS_QUEUE", "jobs")  # must match worker

MINIO_HOST = os.getenv("MINIO_HOST", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "uploads")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() in {"1", "true", "yes"}

# Admin credentials (for /token). Configure via env.
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

# -------------------- Clients --------------------
redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)

minio_client = Minio(
    MINIO_HOST,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=MINIO_SECURE
)

# Ensure bucket exists
try:
    if not minio_client.bucket_exists(MINIO_BUCKET):
        minio_client.make_bucket(MINIO_BUCKET)
except Exception:
    # will surface on upload if misconfigured
    pass

# -------------------- App & Auth --------------------
security = HTTPBearer()
app = FastAPI(title="Sentinel AI - Submission API (aligned with worker)")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# -------------------- Models --------------------
class URLRequest(BaseModel):
    url: HttpUrl

# -------------------- Routes --------------------
@app.post("/token")
def login(username: str = Form(...), password: str = Form(...)):
    """
    Obtain JWT token (simple admin check). Configure ADMIN_USERNAME / ADMIN_PASSWORD via env.
    """
    if username != ADMIN_USERNAME or password != ADMIN_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": username})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/upload", summary="Upload a file for scanning", description="Stores file in MinIO under object name = file_id and enqueues a file job.")
async def upload_file(file: UploadFile = File(...), user: dict = Depends(verify_token)):
    """
    Upload file, put to MinIO under object name == file_id, push job to Redis queue {type:file,file_id:...,filename:...}
    """
    file_id = str(uuid.uuid4())
    # Save uploaded content to a temporary location (minio fput_object expects a file path)
    tmp_path = f"/tmp/{file_id}"
    try:
        contents = await file.read()
        with open(tmp_path, "wb") as f:
            f.write(contents)

        # Upload to MinIO using object name = file_id (worker expects to fetch by file_id)
        minio_client.fput_object(MINIO_BUCKET, file_id, tmp_path)

        # Prepare job exactly as worker expects
        job = {"type": "file", "file_id": file_id, "filename": file.filename}
        redis_client.lpush(REDIS_QUEUE, json.dumps(job))

        return {"file_id": file_id, "message": "File submitted for scanning"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {e}")
    finally:
        # Best-effort cleanup of local tmp file
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


@app.post("/submit_url", summary="Submit URL/domain for SSL check")
async def submit_url(request: URLRequest, user: dict = Depends(verify_token)):
    """
    Normalize the URL to hostname and enqueue domain job:
    Worker expects {"type":"domain","domain":"example.com"} (or accepts legacy "url").
    """
    # Normalize to hostname
    from urllib.parse import urlparse
    parsed = urlparse(str(request.url))
    hostname = parsed.hostname or str(request.url)

    job_id = str(uuid.uuid4())
    job = {"type": "domain", "domain": hostname, "job_id": job_id}
    redis_client.lpush(REDIS_QUEUE, json.dumps(job))

    return {"job_id": job_id, "domain": hostname, "message": "Domain submitted for SSL check"}


@app.get("/report/{target}", summary="Fetch a report (file_id or domain)")
async def get_report(target: str, user: dict = Depends(verify_token)):
    """
    Fetch the report produced by the worker.
    Worker writes JSON to Redis key: report:{file_id_or_domain}
    Returns a consistent structured response when missing.
    """
    try:
        raw = redis_client.get(f"report:{target}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Redis error: {e}")

    if not raw:
        return {
            "target": target,
            "status": "pending",
            "severity": None,
            "findings": [],
            "timestamp": datetime.utcnow().isoformat(),
            "message": "Report not found yet"
        }

    # parse JSON produced by worker
    try:
        report_data = json.loads(raw)
    except Exception:
        # defensively return raw string in 'raw' field if parsing fails
        report_data = {"raw": raw}

    # If the worker already produced a structured report, return as-is.
    # Optionally, normalize to your front-end schema here — we'll return the worker report directly.
    return {"target": target, "report": report_data, "message": "Report retrieved successfully"}

