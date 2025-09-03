# import os
# import json
# import hashlib
# import tempfile
# import time
# import logging
# import ssl
# import socket
# from logging.handlers import RotatingFileHandler
# from datetime import datetime

# import yara
# import pyclamd
# from redis import Redis
# from minio import Minio
# from minio.error import S3Error

# # ----------------------
# # Logging
# # ----------------------
# LOG_DIR = "/var/log/mvp-scanner"
# os.makedirs(LOG_DIR, exist_ok=True)
# LOG_FILE = os.path.join(LOG_DIR, "worker.log")
# LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

# logger = logging.getLogger("static-worker")
# logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
# if logger.hasHandlers():
#     logger.handlers.clear()

# fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
# fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
# logger.addHandler(fh)

# ch = logging.StreamHandler()
# ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
# logger.addHandler(ch)

# logger.propagate = False

# # ----------------------
# # Config & Clients
# # ----------------------
# REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
# REDIS_QUEUE = os.getenv("REDIS_QUEUE", "jobs")
# redis = Redis.from_url(REDIS_URL, decode_responses=True)

# MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
# MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
# MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
# MINIO_BUCKET = os.getenv("MINIO_BUCKET", "uploads")
# MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() in {"1", "true", "yes"}

# minio_client = Minio(
#     MINIO_ENDPOINT,
#     access_key=MINIO_ACCESS_KEY,
#     secret_key=MINIO_SECRET_KEY,
#     secure=MINIO_SECURE,
# )

# # Prepare YARA rules path (optional)
# YARA_RULES_PATH = os.getenv("YARA_RULES_PATH", "/app/rules")
# _yara_rules = None

# def load_yara_rules():
#     global _yara_rules
#     if _yara_rules is not None:
#         return _yara_rules
#     try:
#         if os.path.isdir(YARA_RULES_PATH):
#             all_files = [os.path.join(YARA_RULES_PATH, f) for f in sorted(os.listdir(YARA_RULES_PATH)) if f.endswith((".yar", ".yara"))]
#             if all_files:
#                 namespaces = {f"r{i}": path for i, path in enumerate(all_files)}
#                 _yara_rules = yara.compile(filepaths=namespaces)
#                 logger.info("Loaded %d YARA rule files from %s", len(all_files), YARA_RULES_PATH)
#             else:
#                 logger.info("No YARA rule files found in %s", YARA_RULES_PATH)
#                 _yara_rules = None
#         else:
#             logger.info("YARA rules path not found: %s", YARA_RULES_PATH)
#             _yara_rules = None
#     except Exception as e:
#         logger.exception("Failed to load YARA rules: %s", e)
#         _yara_rules = None
#     return _yara_rules

# def yara_scan_file(path):
#     rules = load_yara_rules()
#     if not rules:
#         return []
#     try:
#         matches = rules.match(path)
#         return [m.rule for m in matches]
#     except Exception as e:
#         logger.exception("YARA scanning error: %s", e)
#         return []

# # ----------------------
# # ClamAV client (reused)
# # ----------------------
# _clamd = None
# def get_clamd():
#     global _clamd
#     if _clamd is not None:
#         return _clamd
#     host = os.getenv("CLAMAV_HOST", "clamav")
#     port = int(os.getenv("CLAMAV_PORT", "3310"))
#     try:
#         c = pyclamd.ClamdNetworkSocket(host=host, port=port)
#         c.ping()
#         _clamd = c
#         logger.info("Connected to ClamAV at %s:%s", host, port)
#         return _clamd
#     except Exception as e:
#         logger.warning("ClamAV not available at %s:%s -> %s", host, port, e)
#         _clamd = None
#         return None

# def clamav_scan_file(path):
#     c = get_clamd()
#     if not c:
#         return {"status": "ERROR", "reason": "ClamAV unavailable"}
#     try:
#         res = c.scan_file(path)
#         if not res:
#             return {"status": "CLEAN"}
#         else:
#             return {"status": "INFECTED", "result": res}
#     except Exception as e:
#         logger.exception("ClamAV scan error: %s", e)
#         return {"status": "ERROR", "reason": str(e)}

# # ----------------------
# # Helpers (MinIO fetch, hashing)
# # ----------------------
# def fetch_object_data(bucket: str, object_name: str) -> bytes:
#     """Retrieve the entire object from MinIO safely and return bytes."""
#     response = None
#     data = b""
#     try:
#         response = minio_client.get_object(bucket, object_name)
#         for chunk in response.stream(32 * 1024):
#             if not chunk:
#                 break
#             data += chunk
#         return data
#     except S3Error as e:
#         logger.exception("MinIO get_object S3Error for %s/%s: %s", bucket, object_name, e)
#         raise
#     except Exception as e:
#         logger.exception("MinIO get_object error for %s/%s: %s", bucket, object_name, e)
#         raise
#     finally:
#         if response:
#             try:
#                 response.close()
#                 response.release_conn()
#             except Exception:
#                 pass

# def compute_sha256_bytes(data: bytes) -> str:
#     import hashlib
#     return hashlib.sha256(data).hexdigest()

# # ----------------------
# # SSL / domain checks
# # ----------------------
# def check_ssl_domain(domain: str, port: int = 443, timeout: float = 6.0):
#     """
#     Lightweight SSL inspection:
#       - handshake (tls version + cipher)
#       - get server cert (der) and fingerprint
#       - basic expiry checks
#     """
#     report = {
#         "domain": domain,
#         "ok": False,
#         "tls_version": None,
#         "cipher": None,
#         "not_before": None,
#         "not_after": None,
#         "expiry_days": None,
#         "fingerprint_sha256": None,
#         "error": None
#     }

#     try:
#         ctx = ssl.create_default_context()
#         # don't fail immediately on hostname; we will still inspect cert
#         # create_connection then wrap for handshake
#         with socket.create_connection((domain, port), timeout=timeout) as sock:
#             sock.settimeout(timeout)
#             with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
#                 report["tls_version"] = ssock.version()
#                 try:
#                     c = ssock.cipher()
#                     report["cipher"] = {"name": c[0], "protocol": c[1], "bits": c[2]} if c else None
#                 except Exception:
#                     report["cipher"] = None

#                 # DER binary cert
#                 try:
#                     der = ssock.getpeercert(binary_form=True)
#                 except Exception:
#                     der = None

#                 # also attempt to get textual cert dict (may be empty if verification fails)
#                 try:
#                     peercert = ssock.getpeercert()
#                 except Exception:
#                     peercert = {}

#         # Fingerprint
#         if der:
#             import hashlib
#             report["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()

#         # parse notBefore / notAfter from peercert if available
#         not_before_raw = peercert.get("notBefore")
#         not_after_raw = peercert.get("notAfter")

#         def _parse_tls_time(raw):
#             # format typically: 'Jun  1 12:00:00 2024 GMT' — be permissive
#             if not raw:
#                 return None
#             for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y GMT"):
#                 try:
#                     return datetime.strptime(raw, fmt)
#                 except Exception:
#                     continue
#             # fallback: return raw string
#             return None

#         nb = _parse_tls_time(not_before_raw)
#         na = _parse_tls_time(not_after_raw)
#         report["not_before"] = nb.isoformat() if nb else None
#         report["not_after"] = na.isoformat() if na else None
#         if na:
#             report["expiry_days"] = (na - datetime.utcnow()).days
#             report["ok"] = (na > datetime.utcnow())

#         return report

#     except socket.timeout:
#         report["error"] = "connection_timeout"
#         return report
#     except ssl.SSLError as e:
#         report["error"] = f"ssl_error: {e}"
#         return report
#     except Exception as e:
#         report["error"] = f"unexpected_error: {e}"
#         return report

# # ----------------------
# # Scanning functions
# # ----------------------
# def process_file_job(job):
#     """
#     Expect job shape:
#       {"type":"file", "file_id":"<uuid>", "filename": "..."}
#     Stores result at redis key: report:{file_id}
#     """
#     file_id = job.get("file_id")
#     if not file_id:
#         logger.warning("File job missing file_id: %s", job)
#         return

#     try:
#         data = fetch_object_data(MINIO_BUCKET, file_id)
#         sha256 = compute_sha256_bytes(data)

#         # write to temp file for YARA/clamav that expect a path
#         with tempfile.NamedTemporaryFile(delete=False) as tmp:
#             tmp.write(data)
#             tmp.flush()
#             tmp_path = tmp.name

#         try:
#             yara_matches = yara_scan_file(tmp_path)
#             clamav_res = clamav_scan_file(tmp_path)
#         finally:
#             try:
#                 os.unlink(tmp_path)
#             except Exception:
#                 pass

#         report = {
#             "file_id": file_id,
#             "sha256": sha256,
#             "size_bytes": len(data),
#             "yara": yara_matches,
#             "clamav": clamav_res,
#             "timestamp": int(time.time())
#         }
#         redis.set(f"report:{file_id}", json.dumps(report))
#         logger.info("Processed file job file_id=%s sha256=%s yara=%d clamav=%s",
#                     file_id, sha256, len(yara_matches), clamav_res.get("status"))
#     except Exception as e:
#         logger.exception("Failed processing file job %s: %s", job, e)
#         redis.set(f"report:{file_id or 'unknown'}", json.dumps({"error": str(e)}))

# def process_domain_job(job):
#     """
#     Expect job shape:
#       {"type":"domain", "domain":"example.com", "job_id":"<uuid>"}  # job_id optional
#       or legacy: {"type":"url", "url":"https://example.com", "job_id":"<uuid>"}
#     Stores results at:
#       - report:{job_id}  (if job_id provided)
#       - report:{domain}
#     """
#     # normalize domain / hostname
#     domain = job.get("domain")
#     if not domain:
#         # if they passed full url in 'url' or 'value', try to extract hostname
#         url_val = job.get("url") or job.get("value")
#         if url_val:
#             from urllib.parse import urlparse
#             try:
#                 domain = urlparse(url_val).hostname or url_val
#             except Exception:
#                 domain = url_val

#     if not domain:
#         logger.warning("Domain job missing domain/url: %s", job)
#         return

#     # optional job id so API can query by id
#     job_id = job.get("job_id") or job.get("file_id") or job.get("id")

#     try:
#         # run SSL check (returns dict)
#         result = check_ssl_domain(domain)

#         # canonical envelope: keeps consistent shape across file/domain jobs
#         envelope = {
#             "job_id": job_id,
#             "domain": domain,
#             "scan_type": "ssl",
#             "result": result,
#             "timestamp": datetime.utcnow().isoformat()
#         }

#         # store under domain key
#         redis.set(f"report:{domain}", json.dumps(envelope))

#         # also store under job_id if present (so GET /report/{job_id} works)
#         if job_id:
#             redis.set(f"report:{job_id}", json.dumps(envelope))

#         logger.info("Processed domain job domain=%s job_id=%s ok=%s expiry_days=%s",
#                     domain, job_id, result.get("ok"), result.get("expiry_days"))
#     except Exception as e:
#         logger.exception("Failed processing domain job %s: %s", job, e)
#         err = {"error": str(e), "domain": domain, "job_id": job_id, "timestamp": datetime.utcnow().isoformat()}
#         # write error under both keys so API sees a result
#         redis.set(f"report:{domain}", json.dumps(err))
#         if job_id:
#             redis.set(f"report:{job_id}", json.dumps(err))

# # ----------------------
# # Main loop
# # ----------------------
# def worker_loop():
#     logger.info("Static worker started; listening for queue '%s' (redis=%s)", REDIS_QUEUE, REDIS_URL)
#     while True:
#         try:
#             item = redis.brpop(REDIS_QUEUE, timeout=5)
#             if not item:
#                 continue
#             _, job_data = item
#             try:
#                 job = json.loads(job_data)
#             except Exception as e:
#                 logger.exception("Invalid job JSON: %s (data=%r)", e, job_data[:200])
#                 continue

#             job_type = job.get("type", "file")
#             if job_type == "file":
#                 process_file_job(job)
#             elif job_type in ("domain", "url"):
#                 # accept both 'domain' and legacy 'url' types
#                 # normalize if user sent 'url' field
#                 if job_type == "url" and "domain" not in job:
#                     # try to extract domain if they passed full url
#                     job["domain"] = job.get("url") or job.get("value")
#                 process_domain_job(job)
#             else:
#                 logger.warning("Unknown job type: %s (job=%s)", job_type, job)
#         except Exception as e:
#             logger.exception("Worker main loop error: %s", e)
#             time.sleep(1.0)

# if __name__ == "__main__":
#     worker_loop()


# worker.py (Updated)

import os
import json
import hashlib
import tempfile
import time
import logging
import ssl
import socket
from logging.handlers import RotatingFileHandler
from datetime import datetime

import yara
import pyclamd
import requests # <-- ADDED IMPORT
from redis import Redis
from minio import Minio
from minio.error import S3Error

# ----------------------
# Logging (No changes)
# ----------------------
LOG_DIR = "/var/log/mvp-scanner"
os.makedirs(LOG_DIR, exist_ok=True)
LOG_FILE = os.path.join(LOG_DIR, "worker.log")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logger = logging.getLogger("static-worker")
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
if logger.hasHandlers():
    logger.handlers.clear()

fh = RotatingFileHandler(LOG_FILE, maxBytes=5_000_000, backupCount=3)
fh.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
logger.addHandler(fh)

ch = logging.StreamHandler()
ch.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s"))
logger.addHandler(ch)

logger.propagate = False

# ----------------------
# Config & Clients (No changes)
# ----------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_QUEUE = os.getenv("REDIS_QUEUE", "jobs")
redis = Redis.from_url(REDIS_URL, decode_responses=True)

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "uploads")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() in {"1", "true", "yes"}

minio_client = Minio(
    MINIO_ENDPOINT,
    access_key=MINIO_ACCESS_KEY,
    secret_key=MINIO_SECRET_KEY,
    secure=MINIO_SECURE,
)

# ----------------------
# Existing File Scanning Functions (No changes)
# ----------------------
YARA_RULES_PATH = os.getenv("YARA_RULES_PATH", "/app/rules")
_yara_rules = None

def load_yara_rules():
    global _yara_rules
    if _yara_rules is not None:
        return _yara_rules
    try:
        if os.path.isdir(YARA_RULES_PATH):
            all_files = [os.path.join(YARA_RULES_PATH, f) for f in sorted(os.listdir(YARA_RULES_PATH)) if f.endswith((".yar", ".yara"))]
            if all_files:
                namespaces = {f"r{i}": path for i, path in enumerate(all_files)}
                _yara_rules = yara.compile(filepaths=namespaces)
                logger.info("Loaded %d YARA rule files from %s", len(all_files), YARA_RULES_PATH)
            else:
                logger.info("No YARA rule files found in %s", YARA_RULES_PATH)
                _yara_rules = None
        else:
            logger.info("YARA rules path not found: %s", YARA_RULES_PATH)
            _yara_rules = None
    except Exception as e:
        logger.exception("Failed to load YARA rules: %s", e)
        _yara_rules = None
    return _yara_rules

def yara_scan_file(path):
    rules = load_yara_rules()
    if not rules:
        return []
    try:
        matches = rules.match(path)
        return [m.rule for m in matches]
    except Exception as e:
        logger.exception("YARA scanning error: %s", e)
        return []

_clamd = None
def get_clamd():
    global _clamd
    if _clamd is not None:
        return _clamd
    host = os.getenv("CLAMAV_HOST", "clamav")
    port = int(os.getenv("CLAMAV_PORT", "3310"))
    try:
        c = pyclamd.ClamdNetworkSocket(host=host, port=port)
        c.ping()
        _clamd = c
        logger.info("Connected to ClamAV at %s:%s", host, port)
        return _clamd
    except Exception as e:
        logger.warning("ClamAV not available at %s:%s -> %s", host, port, e)
        _clamd = None
        return None

def clamav_scan_file(path):
    c = get_clamd()
    if not c:
        return {"status": "ERROR", "reason": "ClamAV unavailable"}
    try:
        res = c.scan_file(path)
        if not res:
            return {"status": "CLEAN"}
        else:
            return {"status": "INFECTED", "result": res}
    except Exception as e:
        logger.exception("ClamAV scan error: %s", e)
        return {"status": "ERROR", "reason": str(e)}

def fetch_object_data(bucket: str, object_name: str) -> bytes:
    response = None
    data = b""
    try:
        response = minio_client.get_object(bucket, object_name)
        for chunk in response.stream(32 * 1024):
            if not chunk:
                break
            data += chunk
        return data
    except S3Error as e:
        logger.exception("MinIO get_object S3Error for %s/%s: %s", bucket, object_name, e)
        raise
    except Exception as e:
        logger.exception("MinIO get_object error for %s/%s: %s", bucket, object_name, e)
        raise
    finally:
        if response:
            try:
                response.close()
                response.release_conn()
            except Exception:
                pass

def compute_sha256_bytes(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()

# ----------------------
# Domain Scanning Functions (Existing and New)
# ----------------------

# --- [NEW] HEADER ANALYSIS FUNCTION ---
def analyze_http_headers(domain: str, timeout: float = 5.0):
    """
    Fetches HTTP headers from a domain, trying HTTPS first then HTTP.
    """
    report = {"checked_urls": [], "headers": None, "status_code": None, "error": None}
    urls_to_try = [f"https://{domain}", f"http://{domain}"]
    
    for url in urls_to_try:
        report["checked_urls"].append(url)
        try:
            # Set a user-agent and disable cert verification for flexibility
            headers = {"User-Agent": "Sentinel-Scanner/1.0"}
            response = requests.get(url, timeout=timeout, allow_redirects=True, verify=False, headers=headers)
            
            # Success! Store headers and status, then stop trying.
            report["headers"] = dict(response.headers)
            report["status_code"] = response.status_code
            report["final_url"] = response.url # URL after redirects
            report["error"] = None # Clear any previous error
            return report
        except requests.exceptions.RequestException as e:
            # Log the error and try the next URL
            error_msg = f"{type(e).__name__}"
            report["error"] = f"Failed to connect to {url}: {error_msg}"
            logger.warning("Header analysis for %s failed: %s", url, e)
            continue
            
    # If both URLs fail, the last error will be in the report
    return report

# --- [NEW] BANNER SCANNING FUNCTION ---
def scan_banners(domain: str, timeout: float = 2.0):
    """
    Connects to common ports on a domain and grabs the initial service banner.
    """
    # Common ports for various services
    ports_to_scan = [21, 22, 25, 80, 110, 143, 443, 3306, 5432, 8080]
    results = {}

    for port in ports_to_scan:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((domain, port))
                
                # Receive up to 1024 bytes for the banner
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                results[port] = banner or "connected_no_banner"
        except socket.timeout:
            results[port] = "no_response_timeout"
        except ConnectionRefusedError:
            results[port] = "connection_refused"
        except OSError as e:
            # Catch other potential connection errors
            results[port] = f"connection_error: {e.strerror}"
        except Exception as e:
            results[port] = f"unexpected_error: {type(e).__name__}"
            
    return results

# --- [EXISTING] SSL / domain checks (No changes to this function) ---
def check_ssl_domain(domain: str, port: int = 443, timeout: float = 6.0):
    """
    Lightweight SSL inspection:
      - handshake (tls version + cipher)
      - get server cert (der) and fingerprint
      - basic expiry checks
    """
    report = {
        "domain": domain,
        "ok": False,
        "tls_version": None,
        "cipher": None,
        "not_before": None,
        "not_after": None,
        "expiry_days": None,
        "fingerprint_sha256": None,
        "error": None
    }

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                report["tls_version"] = ssock.version()
                try:
                    c = ssock.cipher()
                    report["cipher"] = {"name": c[0], "protocol": c[1], "bits": c[2]} if c else None
                except Exception:
                    report["cipher"] = None

                try:
                    der = ssock.getpeercert(binary_form=True)
                except Exception:
                    der = None

                try:
                    peercert = ssock.getpeercert()
                except Exception:
                    peercert = {}

        if der:
            import hashlib
            report["fingerprint_sha256"] = hashlib.sha256(der).hexdigest()

        not_before_raw = peercert.get("notBefore")
        not_after_raw = peercert.get("notAfter")

        def _parse_tls_time(raw):
            if not raw:
                return None
            for fmt in ("%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"):
                try:
                    return datetime.strptime(raw.replace('  ',' '), fmt)
                except Exception:
                    continue
            return None

        nb = _parse_tls_time(not_before_raw)
        na = _parse_tls_time(not_after_raw)
        report["not_before"] = nb.isoformat() if nb else None
        report["not_after"] = na.isoformat() if na else None
        if na:
            report["expiry_days"] = (na - datetime.utcnow()).days
            report["ok"] = (na > datetime.utcnow())

        return report

    except socket.timeout:
        report["error"] = "connection_timeout"
        return report
    except ssl.SSLError as e:
        report["error"] = f"ssl_error: {e}"
        return report
    except Exception as e:
        report["error"] = f"unexpected_error: {e}"
        return report

# ----------------------
# Job Processing Functions
# ----------------------
def process_file_job(job):
    # (No changes to this function)
    file_id = job.get("file_id")
    if not file_id:
        logger.warning("File job missing file_id: %s", job)
        return

    try:
        data = fetch_object_data(MINIO_BUCKET, file_id)
        sha256 = compute_sha256_bytes(data)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(data)
            tmp.flush()
            tmp_path = tmp.name

        try:
            yara_matches = yara_scan_file(tmp_path)
            clamav_res = clamav_scan_file(tmp_path)
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

        report = {
            "file_id": file_id,
            "sha256": sha256,
            "size_bytes": len(data),
            "yara": yara_matches,
            "clamav": clamav_res,
            "timestamp": int(time.time())
        }
        redis.set(f"report:{file_id}", json.dumps(report))
        logger.info("Processed file job file_id=%s sha256=%s yara=%d clamav=%s",
                    file_id, sha256, len(yara_matches), clamav_res.get("status"))
    except Exception as e:
        logger.exception("Failed processing file job %s: %s", job, e)
        redis.set(f"report:{file_id or 'unknown'}", json.dumps({"error": str(e)}))


# --- [MODIFIED] DOMAIN JOB PROCESSOR ---
def process_domain_job(job):
    """
    Modified to run SSL, Header, and Banner scans.
    """
    domain = job.get("domain")
    if not domain:
        url_val = job.get("url") or job.get("value")
        if url_val:
            from urllib.parse import urlparse
            try:
                domain = urlparse(url_val).hostname or url_val
            except Exception:
                domain = url_val

    if not domain:
        logger.warning("Domain job missing domain/url: %s", job)
        return

    job_id = job.get("job_id") or job.get("file_id") or job.get("id")

    try:
        # Run all domain-related scans
        logger.info("Running domain scans for %s (job_id=%s)", domain, job_id)
        ssl_result = check_ssl_domain(domain)
        headers_result = analyze_http_headers(domain)
        banners_result = scan_banners(domain)

        # Combine results into a structured envelope
        envelope = {
            "job_id": job_id,
            "domain": domain,
            "timestamp": datetime.utcnow().isoformat(),
            "scan_results": {
                "ssl_scan": ssl_result,
                "header_analysis": headers_result,
                "banner_scan": banners_result,
            }
        }

        # Store the comprehensive report under the domain key
        redis.set(f"report:{domain}", json.dumps(envelope))

        # Also store under job_id if present (so GET /report/{job_id} works)
        if job_id:
            redis.set(f"report:{job_id}", json.dumps(envelope))

        logger.info("Processed domain job for domain=%s (job_id=%s)", domain, job_id)

    except Exception as e:
        logger.exception("Failed processing domain job %s: %s", job, e)
        err = {"error": str(e), "domain": domain, "job_id": job_id, "timestamp": datetime.utcnow().isoformat()}
        redis.set(f"report:{domain}", json.dumps(err))
        if job_id:
            redis.set(f"report:{job_id}", json.dumps(err))

# ----------------------
# Main loop (No changes)
# ----------------------
def worker_loop():
    logger.info("Static worker started; listening for queue '%s' (redis=%s)", REDIS_QUEUE, REDIS_URL)
    while True:
        try:
            item = redis.brpop(REDIS_QUEUE, timeout=5)
            if not item:
                continue
            _, job_data = item
            try:
                job = json.loads(job_data)
            except Exception as e:
                logger.exception("Invalid job JSON: %s (data=%r)", e, job_data[:200])
                continue

            job_type = job.get("type", "file")
            if job_type == "file":
                process_file_job(job)
            elif job_type in ("domain", "url"):
                if job_type == "url" and "domain" not in job:
                    job["domain"] = job.get("url") or job.get("value")
                process_domain_job(job)
            else:
                logger.warning("Unknown job type: %s (job=%s)", job_type, job)
        except Exception as e:
            logger.exception("Worker main loop error: %s", e)
            time.sleep(1.0)

if __name__ == "__main__":
    worker_loop()