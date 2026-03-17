# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in FlyingHoneySnitch, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email: **security@ihbv.io**

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to provide a fix within 7 days for critical issues.

## Security Design

FlyingHoneySnitch handles sensitive wireless network data. Key security measures include:

- **Encrypted storage**: AES-256-GCM file encryption with PBKDF2-HMAC-SHA256 key derivation (600,000 iterations)
- **Database encryption**: Optional SQLCipher transparent encryption at rest
- **Tamper-evident audit logging**: HMAC-SHA256 chained append-only log detecting any modifications
- **No credential storage**: The tool never stores WiFi passwords or authentication credentials
- **Passive-only scanning**: Default operation is fully passive (receive-only)

## Responsible Use

This tool is intended for authorized security assessments, network administration, and educational purposes only. Users are responsible for ensuring they have proper authorization before scanning any networks they do not own or have explicit permission to test.
