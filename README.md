# phishing-detector-api

> **URL or email → phishing probability score (0–100).** Detects credential harvesting, brand impersonation, urgency tactics, URL spoofing, homoglyph attacks. Fetches URL content for richer analysis.

[![PyPI](https://img.shields.io/pypi/v/phishing-detector-api?style=flat)](https://pypi.org/project/phishing-detector-api/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Quickstart

```bash
pip install phishing-detector-api
python -m phishing_detector_api "https://suspicious-link.com/verify-account"
python -m phishing_detector_api email.txt --json
cat email_content.txt | python -m phishing_detector_api -
```

## Detection categories

URL structure · Domain spoofing · Homoglyph attacks · Subdomain abuse ·
Credential harvesting · Brand impersonation · Urgency/fear tactics ·
Generic greetings · Link mismatches · Suspicious attachments

## Output includes

- **Score 0–100** with verdict (safe/suspicious/likely_phishing/phishing)
- **Recommended action** — safe to open / do not click / report and delete
- **IOC summary** — suspicious domains, IPs, email addresses
- **User guidance** — plain-English explanation

## License
MIT © [Alper Nabil Gabra Zakher](https://github.com/AlperNab)
