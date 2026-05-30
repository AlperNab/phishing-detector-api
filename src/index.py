#!/usr/bin/env python3
"""
phishing-detector-api — URL or email content → phishing probability score
Analyzes: URL structure, domain age signals, visual spoofing, urgency tactics,
credential harvesting patterns, brand impersonation, technical red flags
"""
import anthropic, json, re, sys, urllib.request
from pathlib import Path

SYSTEM = """You are a cybersecurity analyst specializing in phishing detection and email security.
Analyze this URL or email content for phishing indicators.

Use these proven detection frameworks:
- URL analysis (domain spoofing, subdomain abuse, URL shorteners, homoglyph attacks)
- Content analysis (urgency, fear, authority impersonation, credential requests)
- Technical signals (HTML obfuscation, tracking pixels, suspicious form actions)
- Brand impersonation (logo abuse, color mimicry, familiar-looking layouts)

Return ONLY valid JSON — no markdown, no explanation.

{
  "input_type": "url|email|both",
  "phishing_score": number_0_to_100,
  "verdict": "safe|suspicious|likely_phishing|phishing",
  "confidence": "high|medium|low",
  "threat_category": "credential_harvesting|malware_delivery|business_email_compromise|spear_phishing|smishing|vishing|brand_impersonation|advance_fee|lottery|romance|investment|other|none",
  "impersonated_brand": "string or null",
  "url_analysis": {
    "url": "string or null",
    "domain": "string or null",
    "legitimate_domain": "string or null",
    "domain_similarity_score": number_0_to_100,
    "suspicious_indicators": [
      {
        "indicator": "description",
        "severity": "critical|high|medium|low",
        "detail": "specific evidence"
      }
    ],
    "uses_https": true_or_false,
    "uses_url_shortener": true_or_false,
    "has_ip_address": true_or_false,
    "suspicious_tld": true_or_false,
    "homoglyph_detected": true_or_false,
    "excessive_subdomains": true_or_false
  },
  "content_analysis": {
    "urgency_tactics": ["list of urgency phrases found"],
    "fear_tactics": ["list of fear-inducing language"],
    "authority_claims": ["impersonated authorities or brands"],
    "credential_request": true_or_false,
    "financial_request": true_or_false,
    "grammar_errors": "none|minor|significant",
    "generic_greeting": true_or_false,
    "suspicious_attachments": ["list of mentioned or detected"],
    "link_mismatch": true_or_false,
    "sensitive_info_requested": ["SSN","password","card number","..."]
  },
  "technical_indicators": [
    {"indicator":"string","severity":"critical|high|medium|low"}
  ],
  "social_engineering_tactics": ["list of psychological manipulation techniques used"],
  "recommended_action": "safe_to_open|do_not_click|report_and_delete|quarantine|contact_IT",
  "user_guidance": "plain-English explanation of what to do and why",
  "false_positive_notes": "reasons why this might be legitimate if verdict is suspicious/phishing",
  "ioc_summary": {
    "domains": ["suspicious domains found"],
    "ips": ["suspicious IPs if found"],
    "email_addresses": ["suspicious email addresses"]
  }
}"""

def analyze(source: str) -> dict:
    client = anthropic.Anthropic()
    # Try to fetch URL content for richer analysis
    extra_content = ""
    is_url = source.strip().startswith("http")
    if is_url:
        try:
            req = urllib.request.Request(source.strip(), headers={"User-Agent":"Mozilla/5.0 PhishDetect/1.0"})
            html = urllib.request.urlopen(req, timeout=8).read().decode("utf-8",errors="replace")[:15000]
            extra_content = f"\n\nPage content (first 15000 chars):\n{re.sub(chr(10)+r'{3,}',chr(10)*2,re.sub(r'<[^>]+>',' ',html))[:8000]}"
        except Exception:
            extra_content = "\n[Could not fetch URL content]"

    prompt = f"Analyze for phishing:\n\n{source}{extra_content}"
    resp = client.messages.create(
        model="claude-sonnet-4-20250514", max_tokens=2000, system=SYSTEM,
        messages=[{"role":"user","content":prompt}]
    )
    raw = re.sub(r'^```(?:json)?\s*','',resp.content[0].text.strip(),flags=re.MULTILINE)
    raw = re.sub(r'\s*```$','',raw,flags=re.MULTILINE)
    return json.loads(raw)

VERDICT_COLOR = {"safe":"\033[92m","suspicious":"\033[93m","likely_phishing":"\033[91m","phishing":"\033[91m"}
VERDICT_ICON = {"safe":"✅","suspicious":"⚠️","likely_phishing":"🚨","phishing":"🚫"}
SEV_ICON = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵"}
ACTION_ICON = {"safe_to_open":"✅","do_not_click":"🚫","report_and_delete":"🗑","quarantine":"🔒","contact_IT":"📞"}
R = "\033[0m"

def print_report(r: dict):
    verdict = r.get("verdict","suspicious")
    score = r.get("phishing_score",0)
    color = VERDICT_COLOR.get(verdict,"")
    score_bar = "█" * (score//10) + "░" * (10 - score//10)

    print(f"\n{'═'*60}")
    print(f"  PHISHING DETECTOR")
    print(f"  {VERDICT_ICON.get(verdict,'')} {color}{verdict.upper().replace('_',' ')}{R}")
    print(f"  Score: [{score_bar}] {score}/100 | Confidence: {r.get('confidence','?')}")
    print(f"{'═'*60}")

    if r.get("impersonated_brand"):
        print(f"\n  ⚠ Impersonating: {r['impersonated_brand']}")
    if r.get("threat_category") and r["threat_category"] != "none":
        print(f"  Threat type: {r['threat_category'].replace('_',' ').upper()}")

    url = r.get("url_analysis",{})
    if url.get("suspicious_indicators"):
        print(f"\n  URL RED FLAGS")
        for ind in url["suspicious_indicators"]:
            print(f"  {SEV_ICON.get(ind.get('severity','low'),'')} {ind.get('indicator','')}")
            if ind.get("detail"): print(f"     {ind['detail'][:80]}")

    content = r.get("content_analysis",{})
    urgency = content.get("urgency_tactics",[])
    fear = content.get("fear_tactics",[])
    creds = content.get("sensitive_info_requested",[])
    if urgency or fear or creds:
        print(f"\n  SOCIAL ENGINEERING")
        for u in urgency[:2]: print(f"  ⏰ Urgency: \"{u}\"")
        for f in fear[:2]: print(f"  😨 Fear: \"{f}\"")
        if creds: print(f"  🔑 Requesting: {', '.join(creds)}")
        if content.get("credential_request"): print(f"  🚨 Credential harvest detected")
        if content.get("generic_greeting"): print(f"  ⚠ Generic greeting (not personalized)")
        if content.get("grammar_errors") and content["grammar_errors"] != "none":
            print(f"  ⚠ Grammar errors: {content['grammar_errors']}")

    tech = r.get("technical_indicators",[])
    if tech:
        print(f"\n  TECHNICAL INDICATORS")
        for t in tech:
            print(f"  {SEV_ICON.get(t.get('severity','low'),'')} {t.get('indicator','')}")

    action = r.get("recommended_action","do_not_click")
    print(f"\n  ACTION: {ACTION_ICON.get(action,'')} {action.upper().replace('_',' ')}")
    print(f"\n  {r.get('user_guidance','')}")

    fp = r.get("false_positive_notes","")
    if fp and verdict in ("suspicious","likely_phishing"):
        print(f"\n  Note: {fp}")
    print(f"{'═'*60}\n")

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Detect phishing in URLs or email content")
    p.add_argument("source", help="URL, email file, or '-' for stdin")
    p.add_argument("--json",action="store_true")
    a = p.parse_args()
    src = sys.stdin.read() if a.source=="-" else (Path(a.source).read_text(encoding="utf-8",errors="replace") if Path(a.source).exists() else a.source)
    r = analyze(src)
    if a.json: print(json.dumps(r,indent=2,ensure_ascii=False))
    else: print_report(r)
