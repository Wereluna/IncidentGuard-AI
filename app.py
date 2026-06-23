import os
import json
import sqlite3
import re
import threading
import time
from datetime import datetime
from flask import Flask, render_template, request, jsonify
from google import genai
from google.genai import types


app = Flask(__name__)
app.jinja_env.globals.update(enumerate=enumerate)

client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
# ── SQLite memory ─────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("incidents.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT,
            severity        TEXT,
            score           INTEGER,
            errors          INTEGER,
            warnings        INTEGER,
            critical_count  INTEGER,
            root_cause      TEXT,
            recommendations TEXT,
            log_snippet     TEXT,
            source_ip       TEXT,
            escalated       INTEGER DEFAULT 0,
            auto_detected   INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

init_db()

def save_incident(data: dict):
    conn = sqlite3.connect("incidents.db")
    conn.execute("""
        INSERT INTO incidents
        (timestamp, severity, score, errors, warnings, critical_count,
         root_cause, recommendations, log_snippet, source_ip, escalated, auto_detected)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        data.get("severity", "LOW"),
        data.get("score", 0),
        data.get("errors", 0),
        data.get("warnings", 0),
        data.get("critical_count", 0),
        data.get("root_cause", ""),
        json.dumps(data.get("recommendations", [])),
        data.get("log_snippet", ""),
        data.get("source_ip", "unknown"),
        1 if data.get("escalated") else 0,
        1 if data.get("auto_detected") else 0
    ))
    conn.commit()
    conn.close()

def get_history(limit=8):
    conn = sqlite3.connect("incidents.db")
    rows = conn.execute("""
        SELECT timestamp, severity, score, root_cause, source_ip, escalated, auto_detected
        FROM incidents ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [{
        "timestamp": r[0][:16],
        "severity": r[1],
        "score": r[2],
        "root_cause": r[3],
        "source_ip": r[4],
        "escalated": bool(r[5]),
        "auto_detected": bool(r[6])
    } for r in rows]

def get_ip_incident_count(ip: str) -> int:
    if not ip or ip == "unknown":
        return 0
    conn = sqlite3.connect("incidents.db")
    count = conn.execute(
        "SELECT COUNT(*) FROM incidents WHERE source_ip=?", (ip,)
    ).fetchone()[0]
    conn.close()
    return count

def get_stats():
    conn = sqlite3.connect("incidents.db")
    total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    escalated = conn.execute("SELECT COUNT(*) FROM incidents WHERE escalated=1").fetchone()[0]
    auto = conn.execute("SELECT COUNT(*) FROM incidents WHERE auto_detected=1").fetchone()[0]
    critical = conn.execute("SELECT COUNT(*) FROM incidents WHERE severity='CRITICAL'").fetchone()[0]
    conn.close()
    return {"total": total, "escalated": escalated, "auto_detected": auto, "critical": critical}

# ── Tool 1: Log Parser ────────────────────────────────────────────────────────
def tool_parse_log(content: str) -> dict:
    errors   = len(re.findall(r'\bERROR\b',    content, re.IGNORECASE))
    warnings = len(re.findall(r'\bWARNING\b',  content, re.IGNORECASE))
    critical = len(re.findall(r'\bCRITICAL\b', content, re.IGNORECASE))
    score = min(critical * 20 + errors * 10 + warnings * 5, 100)
    if score < 20:   severity = "LOW"
    elif score < 50: severity = "MEDIUM"
    elif score < 80: severity = "HIGH"
    else:            severity = "CRITICAL"
    # extract first suspicious IP
    ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
    source_ip = ips[0] if ips else "unknown"
    snippet = "\n".join(content.strip().splitlines()[:40])
    return dict(errors=errors, warnings=warnings, critical_count=critical,
                score=score, severity=severity, source_ip=source_ip, snippet=snippet)

# ── Tool 2: Gemini Root Cause ─────────────────────────────────────────────────
def tool_root_cause(parsed: dict, history: list) -> str:
    history_text = ""
    if history:
        history_text = "Recent incident memory:\n" + "\n".join(
            f"- {h['timestamp']} | {h['severity']} | IP:{h['source_ip']} | {h['root_cause'][:80]}"
            for h in history[:4]
        )
    prompt = f"""You are a senior cybersecurity AI agent investigating a security incident.

Log snippet:
{parsed['snippet']}

Stats: {parsed['critical_count']} CRITICAL, {parsed['errors']} ERRORS, {parsed['warnings']} WARNINGS
Score: {parsed['score']}/100 | Severity: {parsed['severity']} | Source IP: {parsed['source_ip']}

{history_text}

Write a specific 2-3 sentence ROOT CAUSE identifying:
- The exact type of attack or failure
- Which system/service is targeted
- Any pattern match from memory

Respond with ONLY the root cause. No headers, no bullets."""
def tool_root_cause(parsed: dict, history: list) -> str:
    ...

    try:
        response = client.models.generate_content(
            ...
        )
        return response.text.strip()

    except Exception as e:
        return f"Root cause analysis unavailable: {str(e)}"

# ── Tool 3: Gemini Recommendations ───────────────────────────────────────────
def tool_recommendations(parsed: dict, root_cause: str, escalated: bool) -> list:
    escalation_note = "NOTE: This IP has triggered multiple incidents — include immediate blocking steps." if escalated else ""
    prompt = f"""You are a cybersecurity AI agent. Provide exactly 5 specific remediation steps.

Severity: {parsed['severity']}
Root cause: {root_cause}
Source IP: {parsed['source_ip']}
{escalation_note}

Rules:
- Be SPECIFIC to this incident
- Each step must be one actionable sentence
- Number each line 1-5
- No markdown, no bold

Format:
1. [action]
2. [action]"""
    try:
        response = model.generate_content(prompt)
        lines = response.text.strip().splitlines()
        recs = []
        for line in lines:
            line = line.strip()
            if line and line[0].isdigit():
                cleaned = re.sub(r'^\d+[\.\)]\s*', '', line)
                if cleaned:
                    recs.append(cleaned)
        return recs[:5] if recs else ["Escalate to security team immediately."]
    except Exception as e:
        return [f"Recommendations unavailable: {str(e)}"]

# ── Tool 4: Escalation Decision ───────────────────────────────────────────────
def tool_escalation_check(parsed: dict, source_ip: str) -> dict:
    ip_count = get_ip_incident_count(source_ip)
    escalated = False
    escalation_reason = None

    if parsed["severity"] == "CRITICAL":
        escalated = True
        escalation_reason = "CRITICAL severity detected — immediate escalation triggered"
    elif ip_count >= 2:
        escalated = True
        escalation_reason = f"IP {source_ip} has triggered {ip_count + 1} incidents — recurring attacker escalation"
    elif parsed["score"] >= 70:
        escalated = True
        escalation_reason = f"Threat score {parsed['score']}/100 exceeds escalation threshold"

    return {"escalated": escalated, "reason": escalation_reason, "ip_count": ip_count}

# ── Tool 5: Severity Verification ─────────────────────────────────────────────
def tool_verify_severity(parsed: dict, root_cause: str) -> str:
    prompt = f"""Root cause: "{root_cause}"
Stats: {parsed['errors']} errors, {parsed['warnings']} warnings, score {parsed['score']}/100

Reply with ONLY one word — LOW, MEDIUM, HIGH, or CRITICAL:"""
    try:
        response = model.generate_content(prompt)
        verdict = response.text.strip().upper()
        return verdict if verdict in ("LOW","MEDIUM","HIGH","CRITICAL") else parsed["severity"]
    except:
        return parsed["severity"]

# ── Master Agent Orchestrator ─────────────────────────────────────────────────
def run_agent(content: str, auto_detected: bool = False) -> dict:
    # Step 1: Parse
    parsed = tool_parse_log(content)

    # Step 2: Memory context
    history = get_history(5)

    # Step 3: Escalation check (before Gemini to save quota)
    escalation = tool_escalation_check(parsed, parsed["source_ip"])

    # Step 4: Root cause (Gemini call 1)
    root_cause = tool_root_cause(parsed, history)

    # Step 5: Recommendations (Gemini call 2)
    recommendations = tool_recommendations(parsed, root_cause, escalation["escalated"])

    # Step 6: Verify severity (Gemini call 3)
    final_severity = tool_verify_severity(parsed, root_cause)

    # Step 7: Override if escalated
    if escalation["escalated"] and final_severity in ("LOW", "MEDIUM"):
        final_severity = "HIGH"

    result = {
        **parsed,
        "severity": final_severity,
        "root_cause": root_cause,
        "recommendations": recommendations,
        "log_snippet": parsed["snippet"],
        "history": history,
        "escalated": escalation["escalated"],
        "escalation_reason": escalation["reason"],
        "ip_count": escalation["ip_count"],
        "auto_detected": auto_detected
    }

    # Step 8: Save to memory
    save_incident(result)
    return result

# ── Autonomous Monitor (runs in background thread) ────────────────────────────
SIMULATED_LOGS = [
    """2026-06-23 03:12:01 WARNING Failed login attempt from 45.33.32.156
2026-06-23 03:12:03 ERROR SSH brute force detected from 45.33.32.156
2026-06-23 03:12:05 CRITICAL Unauthorized access granted to root from 45.33.32.156""",

    """2026-06-23 03:45:10 WARNING Unusual outbound traffic spike detected
2026-06-23 03:45:12 WARNING DNS query to suspicious domain malware-c2.net
2026-06-23 03:45:15 ERROR Data exfiltration pattern detected — 1.2GB transfer""",

    """2026-06-23 04:01:00 INFO System health check passed
2026-06-23 04:01:05 INFO Backup completed successfully
2026-06-23 04:01:10 WARNING Disk usage at 87% on /var/log""",
]

auto_monitor_running = False
auto_monitor_status = {"last_run": None, "incidents_detected": 0}

def autonomous_monitor():
    global auto_monitor_running, auto_monitor_status
    log_index = 0
    while auto_monitor_running:
        try:
            log_content = SIMULATED_LOGS[log_index % len(SIMULATED_LOGS)]
            parsed = tool_parse_log(log_content)
            if parsed["score"] > 15:  # only analyze non-trivial logs
                run_agent(log_content, auto_detected=True)
                auto_monitor_status["incidents_detected"] += 1
            auto_monitor_status["last_run"] = datetime.now().strftime("%H:%M:%S")
            log_index += 1
        except Exception as e:
            print(f"Monitor error: {e}")
        time.sleep(45)  # scan every 45 seconds

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    error_msg = None

    if request.method == 'POST':
        file = request.files.get('logfile')
        if file and file.filename:
            try:
                content = file.read().decode('utf-8')
                result = run_agent(content, auto_detected=False)
            except Exception as e:
                error_msg = str(e)
        else:
            error_msg = "Please select a log file before clicking Analyze."

    history = get_history()
    stats = get_stats()
    return render_template('index.html',
                           result=result,
                           history=history,
                           stats=stats,
                           error_msg=error_msg,
                           monitor_status=auto_monitor_status,
                           monitor_running=auto_monitor_running)

@app.route('/monitor/start', methods=['POST'])
def start_monitor():
    global auto_monitor_running
    if not auto_monitor_running:
        auto_monitor_running = True
        t = threading.Thread(target=autonomous_monitor, daemon=True)
        t.start()
    return jsonify({"status": "started"})

@app.route('/monitor/stop', methods=['POST'])
def stop_monitor():
    global auto_monitor_running
    auto_monitor_running = False
    return jsonify({"status": "stopped"})

@app.route('/api/history')
def api_history():
    return jsonify(get_history(20))

@app.route('/api/stats')
def api_stats():
    return jsonify(get_stats())

@app.route('/api/monitor-status')
def monitor_status_api():
    return jsonify({**auto_monitor_status, "running": auto_monitor_running})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
