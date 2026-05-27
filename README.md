# Secure S3 File Sharing Portal

A secure, lightweight file sharing portal built on Amazon S3 with pre-signed URLs.

**🔗 Live Demo:** https://kdeath83.github.io/s3-secure-share/

## Features

- **Pre-signed Upload URLs** — Direct browser-to-S3 uploads, no file touches your server
- **Pre-signed Download URLs** — Time-limited, revocable access links
- **Drag & Drop Interface** — Modern web UI
- **Configurable TTL** — Set link expiration per file
- **Password Protection** — Optional access control
- **Dark Theme** — AWS console inspired
- **Zero Persistent Storage** — Files live in S3 only, metadata in memory (or DynamoDB for production)

## Quick Deploy

### One-Click AWS CloudFormation

| Region | Deploy |
|--------|--------|
| 🇺🇸 **US East (N. Virginia)** | [![Deploy to AWS](https://img.shields.io/badge/Deploy%20to%20AWS-FF9900?style=flat&logo=amazon-aws&logoColor=white)](https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/create/review?templateURL=https://raw.githubusercontent.com/kdeath83/s3-secure-share/master/template.yaml&stackName=s3-secure-share) |
| 🇦🇺 **Asia Pacific (Sydney)** | [![Deploy to AWS](https://img.shields.io/badge/Deploy%20to%20AWS-FF9900?style=flat&logo=amazon-aws&logoColor=white)](https://console.aws.amazon.com/cloudformation/home?region=ap-southeast-2#/stacks/create/review?templateURL=https://raw.githubusercontent.com/kdeath83/s3-secure-share/master/template.yaml&stackName=s3-secure-share) |
| 🇪🇺 **Europe (Ireland)** | [![Deploy to AWS](https://img.shields.io/badge/Deploy%20to%20AWS-FF9900?style=flat&logo=amazon-aws&logoColor=white)](https://console.aws.amazon.com/cloudformation/home?region=eu-west-1#/stacks/create/review?templateURL=https://raw.githubusercontent.com/kdeath83/s3-secure-share/master/template.yaml&stackName=s3-secure-share) |

**What gets created:** Lambda + API Gateway + S3 Bucket + IAM Role + CloudWatch Logs

### SAM CLI Deploy

```bash
sam build
sam deploy --guided
```

### Docker

```bash
docker build -t s3-secure-share .
docker run -p 8000:8000 \
  -e AWS_ACCESS_KEY_ID=... \
  -e AWS_SECRET_ACCESS_KEY=... \
  -e S3_BUCKET=... \
  s3-secure-share
```

### Elastic Beanstalk

```bash
eb init -p python-3.11 s3-secure-share
eb create s3-secure-share-env
```

## Quick Start (Local)

```bash
pip install -r requirements.txt
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export S3_BUCKET=your-bucket
python app.py
```

Visit http://localhost:8000

## Architecture

```
Browser → API Gateway → Lambda (FastAPI) → S3 Pre-signed URL → Direct S3 Upload/Download
```

Files never pass through the application server.

## Security Hardening

| Layer | Implementation |
|-------|---------------|
| **Path Traversal** | Filename sanitized with regex |
| **Password Storage** | PBKDF2-HMAC-SHA256 + unique salt |
| **Password Verification** | `hmac.compare_digest()` constant-time |
| **Rate Limiting** | Per-IP: 10 uploads/min, 30 downloads/min |
| **Admin Auth** | `X-Admin-Token` header (not query param) |
| **Security Headers** | CSP, X-Frame-Options, HSTS, X-Content-Type-Options |
| **CORS** | Restricted to specific origins |
| **XSS Prevention** | All user input escaped in frontend |
| **HTTPS** | Optional redirect middleware |
| **Container** | Non-root user (`appuser`) |
| **Audit Logging** | All actions logged with IP and file ID |
| **Input Validation** | Pydantic validators on filename, content-type, size |
| **S3 Security** | Private bucket, pre-signed URLs with TTL |
| **Upload Ownership** | IP-based confirmation check |

## IAM Policy (Least Privilege)

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
      "Resource": "arn:aws:s3:::your-bucket/*"
    }
  ]
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ACCESS_KEY_ID` | AWS access key | Required |
| `AWS_SECRET_ACCESS_KEY` | AWS secret key | Required |
| `AWS_DEFAULT_REGION` | AWS region | `ap-southeast-2` |
| `S3_BUCKET` | S3 bucket name | `secure-share-files` |
| `URL_TTL_SECONDS` | Download URL TTL | `3600` |
| `UPLOAD_URL_TTL` | Upload URL TTL | `300` |
| `MAX_FILE_SIZE_MB` | Max upload size | `500` |
| `ADMIN_PASSWORD` | Admin protection | None |
| `FORCE_HTTPS` | Redirect HTTP→HTTPS | `false` |
| `TRUSTED_HOSTS` | Allowed hosts | `*` |

## License

MIT
