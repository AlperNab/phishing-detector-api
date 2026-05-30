# Phishing Detector Api — Standalone Real GUI Implementation

This folder is now its own runnable project app. It does not depend on the root all-project dashboard at runtime.

## Run

```bash
./run_gui.sh
```

Windows:

```powershell
.\run_gui_windows.ps1
```

Default URL: `http://127.0.0.1:9145`

## What is inside this project folder

- `app/` — FastAPI backend for this project.
- `static/` — elegant browser GUI.
- `plugins/phishing-detector-api.json` — this project’s own feature/customization/input schema.
- `project_config.json` — readable copy of the same project-specific configuration.
- `data/` — local SQLite jobs, uploads, exports.
- `tests/` — verifies this project has a registered real local engine.

## Project-specific scope

- Domain: `Cybersecurity / Email Safety`
- Target user: `Domain operator, business owner, analyst, or team member who needs this workflow executed reliably.`
- Core job: Email/URL → phishing risk assessment
- Suite: `Security Suite`

## Deep features applied

- header analysis
- URL spoof/homoglyph detection
- brand impersonation
- sandbox screenshot
- urgency/social-engineering scoring
- remediation checklist
- training explanation

## Customization controls

- `execution_mode` — Execution mode (select)
- `strictness` — strictness (slider)
- `target_brand` — target brand (text)
- `allow_block_lists` — allow/block lists (text)
- `siem_webhook` — SIEM webhook (text)
- `safe_browsing_mode` — safe browsing mode (select)
- `evidence_depth` — evidence depth (text)
- `output_format` — output format (select)
- `language` — language (select)
- `privacy_mode` — privacy mode (select)
- `confidence_threshold` — Confidence threshold (slider)

## Input fields

- `email` — Email (text) required
- `url` — URL (text) required
- `work_brief` — Work brief / source text / URL / instructions (textarea) required

## External data policy

The local deterministic core is real and executable. Live external systems are not simulated. If Shopify, ATS, ERP, OCR/STT, maps, SERP, market data, medical databases, tax/customs databases, or other live systems are required, this project reports the missing connector/API requirement instead of inventing data.

---

## Final UX/UI Layer

This project now uses the **Security Response Console** pattern.

**UX workflow:** Signal intake → severity/risk → evidence → remediation → report

**Domain components:**
- Severity matrix
- Evidence/IOC panel
- Remediation checklist
- Timeline builder
- Policy/report export

**Quick actions:**
- Triage severity
- Extract indicators
- Build remediation plan
- Prepare incident report

**No fake-data policy:** external/live actions require real connectors or API keys. Missing connectors are reported instead of simulated.
