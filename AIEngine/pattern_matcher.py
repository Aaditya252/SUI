import re
import json

SQLI_PATTERNS = [
    (r"(\bSELECT\b.*\bFROM\b)", 90),
    (r"(\bUNION\b.*\bSELECT\b)", 95),
    (r"(\bDROP\s+TABLE\b)", 95),
    (r"('?\bOR\b.*\b=\b.*')", 85),
    (r"('?\bAND\b.*\b=\b.*')", 80),
    (r"(\bEXEC\b.*\()", 90),
    (r"(\bxp_\w+)", 85),
    (r"(sleep\s*\(\s*\d+\s*\))", 80),
    (r"(\bINSERT\b.*\bINTO\b)", 85),
    (r"(\bDELETE\b.*\bFROM\b)", 85),
    (r"(--.*)", 70),
    (r"(/\*.*\*/)", 70),
    (r"(\bCHAR\b.*\()", 75),
    (r"(\bWAITFOR\b.*\bDELAY\b)", 85),
    (r"(\bINFORMATION_SCHEMA\b)", 80),
]

XSS_PATTERNS = [
    (r"(<script[^>]*>.*?</script>)", 95),
    (r"(javascript\s*:)", 85),
    (r"(onerror\s*=)", 85),
    (r"(onload\s*=)", 80),
    (r"(onclick\s*=)", 80),
    (r"(onmouseover\s*=)", 75),
    (r"(alert\s*\(.*\))", 85),
    (r"(document\.cookie)", 80),
    (r"(<[^>]*\s+src\s*=)", 70),
    (r"(<iframe[^>]*>)", 80),
    (r"(<embed[^>]*>)", 75),
    (r"(<svg[^>]*>.*<script)", 85),
    (r"(fromCharCode)", 75),
    (r"(eval\s*\()", 80),
    (r"(prompt\s*\()", 70),
]

CMD_INJECTION_PATTERNS = [
    (r"(;\s*(rm|cat|wget|curl|bash|sh|nc|python|perl)\s)", 95),
    (r"(\|\s*(rm|cat|wget|curl|bash|sh|nc|python|perl)\s)", 95),
    (r"(`.*\b(rm|cat|wget|curl|bash|sh|nc|python|perl)\b.*`)", 95),
    (r"(\$\(.*\b(rm|cat|wget|curl|bash|sh|nc|python|perl)\b.*\))", 90),
    (r"(\/etc\/passwd)", 85),
    (r"(\/etc\/shadow)", 90),
    (r"(\.env\b)", 70),
    (r"(\/proc\/self\/environ)", 85),
]

PATH_TRAVERSAL_PATTERNS = [
    (r"(\.\.\/+){2,}", 80),
    (r"(\.\.\\){2,}", 80),
    (r"(%2e%2e%2f)", 75),
    (r"(%c0%ae%c0%ae)", 75),
]


def scan_payload(payload):
    if not payload or not isinstance(payload, str):
        return {"detected": False, "threats": [], "max_score": 0}

    threats = []
    max_score = 0

    entries = [
        ("SQL_INJECTION", SQLI_PATTERNS),
        ("XSS", XSS_PATTERNS),
        ("CMD_INJECTION", CMD_INJECTION_PATTERNS),
        ("PATH_TRAVERSAL", PATH_TRAVERSAL_PATTERNS),
    ]

    for threat_type, patterns in entries:
        for pattern, score in patterns:
            if re.search(pattern, payload, re.IGNORECASE):
                threats.append({
                    "type": threat_type,
                    "pattern": pattern,
                    "score": score,
                    "matched": re.search(pattern, payload, re.IGNORECASE).group(0)[:60]
                })
                max_score = max(max_score, score)

    return {
        "detected": max_score >= 40,
        "threats": threats,
        "max_score": max_score,
        "severity": "CRITICAL" if max_score >= 90 else "HIGH" if max_score >= 75 else "MEDIUM" if max_score >= 50 else "LOW" if max_score >= 40 else "NONE"
    }


def scan_request_headers(headers):
    threats = []
    max_score = 0

    user_agent = headers.get("User-Agent", "")
    if not user_agent or user_agent.strip() == "":
        threats.append({"type": "MISSING_USER_AGENT", "score": 30})
        max_score = max(max_score, 30)

    if "Accept" not in headers:
        threats.append({"type": "MISSING_ACCEPT_HEADER", "score": 20})
        max_score = max(max_score, 20)

    for key, value in headers.items():
        if key.lower() in ("x-forwarded-for", "x-real-ip", "client-ip"):
            scan_result = scan_payload(value)
            if scan_result["detected"]:
                threats.extend(scan_result["threats"])
                max_score = max(max_score, scan_result["max_score"])

    return {"detected": max_score >= 40, "threats": threats, "max_score": max_score}


def scan_url_path(path):
    return scan_payload(path)
