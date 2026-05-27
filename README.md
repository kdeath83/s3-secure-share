# Secure S3 File Sharing Portal

A secure, lightweight file sharing portal built on Amazon S3 with pre-signed URLs.

## Features

- **Pre-signed Upload URLs** — Direct browser-to-S3 uploads, no file touches your server
- **Pre-signed Download URLs** — Time-limited, revocable access links
- **Drag & Drop Interface** — Modern web UI
- **Configurable TTL** — Set link expiration per file
- **Password Protection** — Optional access control
- **Dark Theme** — AWS console inspired
- **Zero Persistent Storage** — Files live in S3 only, metadata in memory (or DynamoDB for production)

## Architecture

```
User Browser → FastAPI Backend → S3 Pre-signed URL → Direct S3 Upload/Download
```

Files never pass through the application server. The backend only generates signed URLs and tracks metadata.

## Quick Start

### 1. Configure AWS Credentials

```bash
aws configure
# or set env vars:
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
export AWS_DEFAULT_REGION=ap-southeast-2
```

### 2. Create S3 Bucket

```bash
aws s3 mb s3://your-secure-share-bucket --region ap-southeast-2
aws s3api put-public-access-block --bucket your-secure-share-bucket \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

### 3. Configure CORS

```bash
aws s3api put-bucket-cors --bucket your-secure-share-bucket --cors-configuration file://cors.json
```

See `cors.json` in this repo for the exact configuration.

### 4. Install & Run

```bash
pip install -r requirements.txt
python app.py
```

Visit http://localhost:8000

### 5. Production Deploy

**Option A: Docker**
```bash
docker build -t s3-secure-share .
docker run -p 8000:8000 -e AWS_ACCESS_KEY_ID=... -e AWS_SECRET_ACCESS_KEY=... s3-secure-share
```

**Option B: AWS Elastic Beanstalk**
```bash
eb init -p python-3.11 s3-secure-share
eb create s3-secure-share-env
eb open
```

**Option C: AWS Lambda + API Gateway (Serverless)**
See `serverless/` directory for SAM/CloudFormation template.

## Security Considerations

1. **S3 Bucket is Private** — No public access, all access via pre-signed URLs
2. **URL Expiration** — Default 1 hour for downloads, configurable per file
3. **CORS Restrictions** — Only your domain can upload
4. **Optional Password** — Files can be protected with shareable passwords
5. **HTTPS Only** — Pre-signed URLs work over TLS
6. **IAM Least Privilege** — App only needs `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`

## Security Hardening

This application implements multiple security layers:

| Layer | Implementation |
|-------|---------------|
| **Path Traversal** | Filename sanitized with regex, `os.path.basename()` enforced |
| **Password Storage** | PBKDF2-HMAC-SHA256 with unique salt per file |
| **Password Verification** | `hmac.compare_digest()` constant-time comparison |
| **Rate Limiting** | Per-IP limits: 10 uploads/min, 30 downloads/min, 30 list/min |
| **Admin Auth** | Token via `X-Admin-Token` header (not query param) |
| **Security Headers** | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy |
| **CORS** | Restricted to specific origins, no wildcard |
| **XSS Prevention** | All user input escaped in frontend |
| **HTTPS** | Optional redirect middleware |
| **Container** | Runs as non-root user (`appuser`) |
| **Audit Logging** | All actions logged with IP and file ID |
| **Input Validation** | Pydantic validators on filename, content-type, file size |
| **S3 Security** | Private bucket, pre-signed URLs with TTL, Content-Disposition attachment |
| **Upload Ownership** | IP-based confirmation check |

## IAM Policy for Application (Least Privilege)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject"
      ],
      "Resource": "arn:aws:s3:::your-secure-share-bucket/*"
    }
  ]
}
```

**Note:** `s3:PutObjectAcl` is intentionally excluded to prevent ACL manipulation attacks.

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ACCESS_KEY_ID` | AWS access key | Required |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | Required |
| `AWS_DEFAULT_REGION` | AWS region | `ap-southeast-2` |
| `S3_BUCKET` | S3 bucket name | `secure-share-files` |
| `URL_TTL_SECONDS` | Default download URL TTL | `3600` |
| `UPLOAD_URL_TTL` | Upload URL TTL | `300` |
| `MAX_FILE_SIZE_MB` | Max upload size | `500` |
| `ADMIN_PASSWORD` | Optional admin protection | None |
| `APP_HOST` | Bind host | `0.0.0.0` |
| `APP_PORT` | Bind port | `8000` |
| `FORCE_HTTPS` | Redirect HTTP to HTTPS | `false` |
| `TRUSTED_HOSTS` | Comma-separated allowed hosts | `*` |

## License

MIT
