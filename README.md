# BanglaShield VAPT Console

A defensive security validation console with a Bangladesh flag-inspired interface. It performs safe, passive checks for scope validation, DNS intelligence, TLS posture, HTTP security headers, and professional reporting.

## Features
- Target scope validation (domain, URL, IP, CIDR)
- DNS, SPF, DKIM, DMARC collection
- HTTP entry point discovery with titles and status codes
- TLS protocol support assessment and certificate metadata
- Header hardening checks with professional findings
- Exportable JSON reports for dashboard and SIEM ingestion

## Safe-mode policy
Safe-mode avoids intrusive exploitation. All checks are passive or low-impact header inspections. Manual guidance is provided for deeper validation.

## Quick start
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app/app.py
```
Open `http://localhost:8000` in your browser.
