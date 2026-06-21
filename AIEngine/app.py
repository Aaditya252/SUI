import os
import json
import time
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pattern_matcher import scan_payload, scan_request_headers, scan_url_path
from rate_limiter import rate_limiter
from threat_detector import threat_detector

app = Flask(__name__, static_folder="../ui")
CORS(app)

ANOMALY_LOG = os.path.join(os.path.dirname(__file__), "anomalies.jsonl")
THREAT_LOG = os.path.join(os.path.dirname(__file__), "threats.jsonl")


def log_anomaly(entry):
    try:
        with open(ANOMALY_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def log_threat(entry):
    try:
        with open(THREAT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass


def get_client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


@app.route("/api/security/analyze", methods=["POST"])
def analyze_request():
    ip = get_client_ip()
    data = request.get_json(silent=True) or {}

    allowed, retry_after = rate_limiter.check(ip)
    if not allowed:
        return jsonify({
            "blocked": True,
            "reason": "RATE_LIMITED",
            "retry_after": retry_after,
            "message": f"Rate limited. Retry after {retry_after}s"
        }), 429

    path = data.get("path", request.path)
    body = data.get("body", "")
    query = data.get("query", "")
    headers = data.get("headers", {})
    method = data.get("method", request.method)

    threat_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "ip": ip,
        "method": method,
        "path": path,
        "user_agent": headers.get("User-Agent", "")[:100]
    }

    pattern_result = scan_payload(body)
    header_result = scan_request_headers(headers)
    path_result = scan_url_path(path)
    combined = body + " " + path + " " + query + " " + json.dumps(headers)
    combined_scan = scan_payload(combined)

    all_threats = (
        pattern_result["threats"] +
        header_result["threats"] +
        path_result["threats"]
    )
    max_score = max(
        pattern_result["max_score"],
        header_result["max_score"],
        path_result["max_score"],
        combined_scan["max_score"]
    )

    anomaly_features = {
        "path": path,
        "body": body,
        "query": query,
        "headers": headers,
        "num_params": len(data.get("params", {})),
        "request_rate": rate_limiter.get_stats(ip)["current_count"]
    }
    anomaly_result = threat_detector.analyze(anomaly_features)
    is_malicious = max_score >= 40 or anomaly_result["is_anomaly"]

    threat_log["threats"] = all_threats
    threat_log["max_score"] = max_score
    threat_log["pattern_detected"] = max_score >= 40
    threat_log["anomaly_detected"] = anomaly_result["is_anomaly"]
    threat_log["anomaly_score"] = anomaly_result["anomaly_score"]

    if is_malicious:
        threat_log["action"] = "BLOCKED" if max_score >= 70 or anomaly_result["is_anomaly"] else "WARN"
        log_threat(threat_log)
        threat_detector.learn(anomaly_features, was_malicious=True)

        if max_score >= 70 or anomaly_result["is_anomaly"]:
            return jsonify({
                "blocked": True,
                "reason": "THREAT_DETECTED",
                "severity": pattern_result["severity"] if max_score >= 40 else "ANOMALY",
                "score": max_score,
                "anomaly_score": anomaly_result["anomaly_score"],
                "threats": [t["type"] for t in all_threats[:5]],
                "message": "Request blocked by FluidBLCX AI Security Layer"
            }), 403
    else:
        threat_detector.learn(anomaly_features, was_malicious=False)

    return jsonify({
        "blocked": False,
        "score": max_score,
        "anomaly_score": anomaly_result["anomaly_score"],
        "threats": [t["type"] for t in all_threats[:3]],
        "message": "Request allowed"
    })


@app.route("/api/security/status", methods=["GET"])
def security_status():
    ip = get_client_ip()
    limiter_stats = rate_limiter.get_stats(ip)
    model_stats = threat_detector.get_model_stats()

    threat_count = 0
    try:
        if os.path.exists(THREAT_LOG):
            with open(THREAT_LOG, "r") as f:
                threat_count = sum(1 for _ in f)
    except Exception:
        pass

    return jsonify({
        "status": "active",
        "layer": "FluidBLCX AI Security Shield v1.0",
        "ip": ip,
        "rate_limit": limiter_stats,
        "ml_model": model_stats,
        "total_threats_blocked": threat_count,
        "protection_layers": [
            "Pattern-based threat detection (SQLi, XSS, CMD Injection, Path Traversal)",
            "ML Anomaly Detection (Isolation Forest)",
            "IP Rate Limiting & Auto-Blocking",
            "Header Validation & Honeypot Detection",
            "Real-time threat logging & adaptive learning"
        ],
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/api/security/threats/recent", methods=["GET"])
def recent_threats():
    threats = []
    try:
        if os.path.exists(THREAT_LOG):
            with open(THREAT_LOG, "r") as f:
                for line in f:
                    try:
                        threats.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass
    return jsonify({"threats": threats[-50:], "total": len(threats)})


@app.route("/api/security/logs/anomalies", methods=["GET"])
def anomaly_logs():
    anomalies = []
    try:
        if os.path.exists(ANOMALY_LOG):
            with open(ANOMALY_LOG, "r") as f:
                for line in f:
                    try:
                        anomalies.append(json.loads(line.strip()))
                    except json.JSONDecodeError:
                        continue
    except Exception:
        pass
    return jsonify({"anomalies": anomalies[-100:], "total": len(anomalies)})


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "service": "FluidBLCX AI Security Engine",
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route("/api/security/blocked-ips", methods=["GET"])
def blocked_ips():
    now = time.time()
    blocked = []
    for ip, until in list(rate_limiter.blocked.items()):
        remaining = int(until - now)
        if remaining > 0:
            blocked.append({"ip": ip, "blocked_until": int(until), "remaining_seconds": remaining})
    return jsonify({"blocked_ips": blocked, "count": len(blocked)})


@app.route("/api/security/reset", methods=["POST"])
def reset_limiter():
    ip = get_client_ip()
    if ip in rate_limiter.blocked:
        del rate_limiter.blocked[ip]
    return jsonify({"message": "Rate limit reset", "ip": ip})


if __name__ == "__main__":
    port = int(os.environ.get("AI_ENGINE_PORT", 5001))
    print(f"[AI ENGINE] FluidBLCX AI Security Layer starting on port {port}")
    print(f"[AI ENGINE] Model trained: {threat_detector.trained} | Samples: {len(threat_detector.training_data)}")
    app.run(host="0.0.0.0", port=port, debug=False)
