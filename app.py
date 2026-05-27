from fastapi import FastAPI, HTTPException, Request, Form, Header, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
import boto3
import os
import uuid
import hashlib
import secrets
import re
import html
import logging
import hmac
from datetime import datetime, timedelta
from pydantic import BaseModel, Field, validator
from typing import Optional, List
import uvicorn
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
AWS_REGION = os.getenv('AWS_DEFAULT_REGION', 'ap-southeast-2')
S3_BUCKET = os.getenv('S3_BUCKET', 'secure-share-files')
URL_TTL_SECONDS = int(os.getenv('URL_TTL_SECONDS', '3600'))
UPLOAD_URL_TTL = int(os.getenv('UPLOAD_URL_TTL', '300'))
MAX_FILE_SIZE_MB = int(os.getenv('MAX_FILE_SIZE_MB', '500'))
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', None)
APP_HOST = os.getenv('APP_HOST', '0.0.0.0')
APP_PORT = int(os.getenv('APP_PORT', '8000'))
FORCE_HTTPS = os.getenv('FORCE_HTTPS', 'false').lower() == 'true'
TRUSTED_HOSTS = os.getenv('TRUSTED_HOSTS', '*').split(',')

# Initialize S3 client
s3_client = boto3.client('s3', region_name=AWS_REGION)

# Verify S3 bucket on startup
def verify_s3_bucket():
    try:
        s3_client.head_bucket(Bucket=S3_BUCKET)
        logger.info(f"S3 bucket '{S3_BUCKET}' is accessible")
    except Exception as e:
        logger.error(f"S3 bucket '{S3_BUCKET}' is not accessible: {e}")
        raise RuntimeError(f"S3 bucket '{S3_BUCKET}' is not accessible. Please create it and check permissions.")

verify_s3_bucket()

# In-memory file registry (use DynamoDB for production)
file_registry = {}

# Rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(title="Secure S3 Share")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Security Headers Middleware
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        # Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        # Prevent MIME sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        # XSS protection
        response.headers['X-XSS-Protection'] = '1; mode=block'
        # Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Content Security Policy
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-ancestors 'none';"
        )
        # HSTS (only if HTTPS is forced)
        if FORCE_HTTPS:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        return response

app.add_middleware(SecurityHeadersMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8000", "https://yourdomain.com"],  # Configure for your domains
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["*"],
)

# Trusted host middleware
if TRUSTED_HOSTS != ['*']:
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=TRUSTED_HOSTS)

# HTTPS redirect middleware
@app.middleware("http")
async def https_redirect(request: Request, call_next):
    if FORCE_HTTPS and request.headers.get('x-forwarded-proto') != 'https':
        return RedirectResponse(str(request.url).replace('http://', 'https://'), status_code=301)
    return await call_next(request)

# Static files and templates
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Input validation helpers
SAFE_FILENAME_PATTERN = re.compile(r'^[a-zA-Z0-9_.-]+$')
MAX_FILENAME_LENGTH = 255

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and injection."""
    if not filename:
        return 'unnamed_file'
    
    # Remove path components
    filename = os.path.basename(filename)
    
    # Replace dangerous characters
    filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    
    # Limit length
    if len(filename) > MAX_FILENAME_LENGTH:
        name, ext = os.path.splitext(filename)
        filename = name[:MAX_FILENAME_LENGTH - len(ext)] + ext
    
    return filename

def generate_file_id() -> str:
    """Generate a cryptographically secure file ID."""
    return secrets.token_urlsafe(16)

def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with salt."""
    if not password:
        return None
    salt = secrets.token_hex(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + pwdhash.hex()

def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash in constant time."""
    if not password or not stored_hash:
        return False
    if len(stored_hash) < 64:
        return False
    salt = stored_hash[:32]
    stored_pwdhash = stored_hash[32:]
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hmac.compare_digest(pwdhash.hex(), stored_pwdhash)

# Models
class FileUploadRequest(BaseModel):
    filename: str = Field(..., max_length=MAX_FILENAME_LENGTH)
    content_type: str = Field(default="application/octet-stream", max_length=100)
    file_size: int = Field(..., gt=0, le=500*1024*1024)  # Max 500MB
    password: Optional[str] = Field(None, max_length=128)
    ttl_hours: Optional[int] = Field(default=24, ge=0, le=720)
    
    @validator('filename')
    def validate_filename(cls, v):
        sanitized = sanitize_filename(v)
        if not sanitized or sanitized == 'unnamed_file':
            raise ValueError('Invalid filename')
        return sanitized
    
    @validator('content_type')
    def validate_content_type(cls, v):
        allowed_types = [
            'application/pdf', 'application/zip', 'application/octet-stream',
            'image/', 'video/', 'audio/', 'text/',
            'application/json', 'application/xml',
            'application/msword', 'application/vnd.openxmlformats',
            'application/vnd.ms-excel', 'application/vnd.ms-powerpoint'
        ]
        if not any(v.startswith(t.rstrip('/')) for t in allowed_types):
            raise ValueError('Content type not allowed')
        return v

class FileResponse(BaseModel):
    file_id: str
    filename: str
    size: int
    content_type: str
    uploaded_at: str
    expires_at: Optional[str] = None
    password_protected: bool
    download_url: Optional[str] = None

# S3 helpers
def generate_presigned_upload_url(file_id: str, content_type: str, file_size: int):
    key = f"uploads/{file_id}"
    conditions = [
        ["content-length-range", 1, file_size + 1024]  # Allow slight variance
    ]
    url = s3_client.generate_presigned_url(
        'put_object',
        Params={
            'Bucket': S3_BUCKET,
            'Key': key,
            'ContentType': content_type,
        },
        ExpiresIn=UPLOAD_URL_TTL
    )
    return url, key

def generate_presigned_download_url(key: str, filename: str, expiration: int = URL_TTL_SECONDS):
    url = s3_client.generate_presigned_url(
        'get_object',
        Params={
            'Bucket': S3_BUCKET,
            'Key': key,
            'ResponseContentDisposition': f'attachment; filename="{filename}"'
        },
        ExpiresIn=expiration
    )
    return url

def get_file_size(key: str) -> int:
    try:
        response = s3_client.head_object(Bucket=S3_BUCKET, Key=key)
        return response['ContentLength']
    except s3_client.exceptions.ClientError as e:
        logger.warning(f"Failed to get file size for {key}: {e}")
        return 0
    except Exception as e:
        logger.error(f"Unexpected error getting file size for {key}: {e}")
        return 0

# Audit logging
def log_action(action: str, file_id: str, ip: str, details: str = ""):
    logger.info(f"AUDIT: {action} | file_id={file_id} | ip={ip} | {details}")

# Routes
@app.get("/", response_class=HTMLResponse)
@limiter.limit("30/minute")
async def home(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "max_file_size": MAX_FILE_SIZE_MB,
        "aws_region": AWS_REGION,
        "bucket": S3_BUCKET
    })

@app.post("/api/upload-url")
@limiter.limit("10/minute")
async def get_upload_url(request: Request, upload_req: FileUploadRequest):
    client_ip = get_remote_address(request)
    
    if upload_req.file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        log_action("UPLOAD_REJECTED_SIZE", "N/A", client_ip, f"size={upload_req.file_size}")
        raise HTTPException(status_code=400, detail=f"File exceeds {MAX_FILE_SIZE_MB}MB limit")
    
    file_id = generate_file_id()
    upload_url, s3_key = generate_presigned_upload_url(file_id, upload_req.content_type, upload_req.file_size)
    
    # Calculate expiration
    expires_at = None
    if upload_req.ttl_hours and upload_req.ttl_hours > 0:
        expires_at = (datetime.utcnow() + timedelta(hours=upload_req.ttl_hours)).isoformat()
    
    # Store metadata
    file_registry[file_id] = {
        'file_id': file_id,
        'filename': upload_req.filename,
        's3_key': s3_key,
        'content_type': upload_req.content_type,
        'size': upload_req.file_size,
        'password_hash': hash_password(upload_req.password) if upload_req.password else None,
        'uploaded_at': datetime.utcnow().isoformat(),
        'expires_at': expires_at,
        'ttl_hours': upload_req.ttl_hours,
        'uploader_ip': client_ip
    }
    
    log_action("UPLOAD_URL_GENERATED", file_id, client_ip, f"filename={upload_req.filename}")
    
    return JSONResponse({
        'file_id': file_id,
        'upload_url': upload_url,
        'expires_in': UPLOAD_URL_TTL
    })

@app.post("/api/confirm-upload/{file_id}")
@limiter.limit("10/minute")
async def confirm_upload(request: Request, file_id: str):
    client_ip = get_remote_address(request)
    
    if file_id not in file_registry:
        log_action("CONFIRM_REJECTED_NOT_FOUND", file_id, client_ip)
        raise HTTPException(status_code=404, detail="File not found")
    
    file_info = file_registry[file_id]
    
    # Verify uploader IP matches (basic ownership check)
    if file_info.get('uploader_ip') != client_ip:
        log_action("CONFIRM_REJECTED_IP", file_id, client_ip)
        raise HTTPException(status_code=403, detail="Upload confirmation rejected")
    
    # Get actual file size from S3
    actual_size = get_file_size(file_info['s3_key'])
    if actual_size > 0:
        file_info['size'] = actual_size
        log_action("UPLOAD_CONFIRMED", file_id, client_ip, f"size={actual_size}")
    else:
        log_action("UPLOAD_CONFIRMED_EMPTY", file_id, client_ip)
    
    return JSONResponse({
        'success': True,
        'file_id': file_id,
        'download_url': f"/api/download/{file_id}"
    })

@app.get("/api/download/{file_id}")
@limiter.limit("30/minute")
async def download_file(request: Request, file_id: str, password: Optional[str] = None):
    client_ip = get_remote_address(request)
    
    if file_id not in file_registry:
        log_action("DOWNLOAD_REJECTED_NOT_FOUND", file_id, client_ip)
        raise HTTPException(status_code=404, detail="File not found or expired")
    
    file_info = file_registry[file_id]
    
    # Check expiration
    if file_info.get('expires_at'):
        expires = datetime.fromisoformat(file_info['expires_at'])
        if datetime.utcnow() > expires:
            log_action("DOWNLOAD_REJECTED_EXPIRED", file_id, client_ip)
            raise HTTPException(status_code=410, detail="File has expired")
    
    # Check password
    if file_info.get('password_hash'):
        if not password:
            log_action("DOWNLOAD_REJECTED_NO_PASSWORD", file_id, client_ip)
            raise HTTPException(status_code=403, detail="Password required")
        if not verify_password(password, file_info['password_hash']):
            log_action("DOWNLOAD_REJECTED_WRONG_PASSWORD", file_id, client_ip)
            raise HTTPException(status_code=403, detail="Invalid password")
    
    # Generate download URL
    download_url = generate_presigned_download_url(file_info['s3_key'], file_info['filename'])
    
    log_action("DOWNLOAD_URL_GENERATED", file_id, client_ip)
    
    return JSONResponse({
        'download_url': download_url,
        'filename': file_info['filename'],
        'expires_in': URL_TTL_SECONDS
    })

@app.get("/api/files")
@limiter.limit("30/minute")
async def list_files(request: Request):
    files = []
    for file_id, info in file_registry.items():
        is_expired = False
        if info.get('expires_at'):
            expires = datetime.fromisoformat(info['expires_at'])
            is_expired = datetime.utcnow() > expires
        
        files.append({
            'file_id': info['file_id'],
            'filename': info['filename'],
            'size': info['size'],
            'content_type': info['content_type'],
            'uploaded_at': info['uploaded_at'],
            'expires_at': info.get('expires_at'),
            'password_protected': info.get('password_hash') is not None,
            'expired': is_expired
        })
    
    # Sort by upload time, newest first
    files.sort(key=lambda x: x['uploaded_at'], reverse=True)
    
    return JSONResponse({'files': files})

@app.delete("/api/files/{file_id}")
@limiter.limit("10/minute")
async def delete_file(request: Request, file_id: str, x_admin_token: Optional[str] = Header(None, alias="X-Admin-Token")):
    client_ip = get_remote_address(request)
    
    if ADMIN_PASSWORD and x_admin_token != ADMIN_PASSWORD:
        log_action("DELETE_REJECTED_AUTH", file_id, client_ip)
        raise HTTPException(status_code=403, detail="Admin access required")
    
    if file_id not in file_registry:
        raise HTTPException(status_code=404, detail="File not found")
    
    file_info = file_registry[file_id]
    
    # Delete from S3
    try:
        s3_client.delete_object(Bucket=S3_BUCKET, Key=file_info['s3_key'])
        log_action("S3_DELETE", file_id, client_ip)
    except Exception as e:
        logger.error(f"S3 delete error for {file_id}: {e}")
    
    # Remove from registry
    del file_registry[file_id]
    log_action("DELETE_SUCCESS", file_id, client_ip)
    
    return JSONResponse({'success': True, 'message': 'File deleted'})

@app.get("/api/health")
async def health_check():
    # Check S3 connectivity
    s3_healthy = False
    try:
        s3_client.head_bucket(Bucket=S3_BUCKET)
        s3_healthy = True
    except:
        pass
    
    return JSONResponse({
        'status': 'healthy' if s3_healthy else 'degraded',
        'bucket': S3_BUCKET,
        'region': AWS_REGION,
        'files_tracked': len(file_registry),
        's3_connected': s3_healthy,
        'timestamp': datetime.utcnow().isoformat()
    })

@app.get("/favicon.ico")
async def favicon():
    return JSONResponse(content={}, status_code=204)

if __name__ == "__main__":
    uvicorn.run(app, host=APP_HOST, port=APP_PORT)