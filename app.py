import os
import json
import sqlite3
import re
from datetime import datetime
from flask import Flask, render_template, request, jsonify
import google.generativeai as genai

app = Flask(__name__)

# ── Gemini setup ──────────────────────────────────────────────────────────────
genai.configure(api_key=os.environ.get("GEMINI_API_KEY"))
model = genai.GenerativeModel("gemini-1.5-flash")

# ── SQLite memory ─────────────────────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect("incidents.db")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            severity  TEXT,
            score     INTEGER,
            errors    INTEGER,
            warnings  INTEGER,
            root_cause      TEXT,
            recommendations TEXT,
            log_snippet     TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def save_incident(data: dict):
    conn = sqlite3.connect("incidents.db")
    conn.execute("""
        INSERT INTO incidents
        (timestamp, severity, score, errors, warnings, root_cause, recommendations, log_snippet)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        datetime.now().isoformat(),
        data["severity"],
        data["score"],
        data["errors"],
        data["warnings"],
        data["root_cause"],
        json.dumps(data["recommendations"]),
        data["log_snippet"]
    ))
    conn.commit()
    conn.close()

def get_history(limit=5):
    conn = sqlite3.connect("incidents.db")
    rows = conn.execute("""
        SELECT timestamp, severity, score, root_cause
        FROM incidents
        ORDER BY id DESC LIMIT ?
    """, (limit,)).fetchall()
    conn.close()
    return [{"timestamp": r[0][:16], "severity": r[1],
             "score": r[2], "root_cause": r[3]} for r in rows]

def get_recurring_patterns():
    conn = sqlite3.connect("incidents.db")
    rows = conn.execute("""
        SELECT severity, COUNT(*) as cnt
        FROM incidents
        GROUP BY severity
        ORDER BY cnt DESC
    """).fetchall()
    conn.close()
    return {r[0]: r[1] for r in rows}

# ── Agent: Step 1 — basic parse ───────────────────────────────────────────────
def parse_log(content: str) -> dict:
    errors   = len(re.findall(r'\bERROR\b',   content, re.IGNORECASE))
    warnings = len(re.findall(r'\bWARNING\b', content, re.IGNORECASE))
    critical = len(re.findall(r'\bCRITICAL\b',content, re.IGNORECASE))
    score = critical * 20 + errors * 10 + warnings * 5
    score = min(score, 100)
    if score < 20:   severity = "LOW"
    elif score < 50: severity = "MEDIUM"
    elif score < 80: severity = "HIGH"
    else:            severity = "CRITICAL"
    snippet = "\n".join(content.strip().splitlines()[:40])
    return dict(errors=errors, warnings=warnings, critical_count=critical,
                score=score, severity=severity, snippet=snippet)

# ── Agent: Step 2 — Gemini root-cause analysis ────────────────────────────────
def gemini_root_cause(parsed: dict, log_snippet: str, history: list) -> str:
    history_text = ""
    if history:
        history_text = "Recent incident history:\n" + "\n".join(
            f"- {h['timestamp']} | {h['severity']} | {h['root_cause']}"
            for h in history
        )

    prompt = f"""You are a senior cybersecurity analyst AI agent.

Analyze this log file and identify the ROOT CAUSE of the incident.

Log snippet (first 40 lines):
{log_snippet}

Parsed stats:
- CRITICAL events: {parsed['critical_count']}
- ERROR events:    {parsed['errors']}
- WARNING events:  {parsed['warnings']}
- Threat score:    {parsed['score']}/100
- Severity:        {parsed['severity']}

{history_text}

Write a concise 2-3 sentence ROOT CAUSE explanation. Be specific about:
- What type of threat or failure this looks like
- What system or service is likely affected
- Whether this matches a recurring pattern from history

Respond with ONLY the root cause text, no headers, no bullet points."""

    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        return f"Root cause analysis unavailable: {str(e)}"

# ── Agent: Step 3 — Gemini dynamic recommendations ───────────────────────────
def gemini_recommendations(parsed: dict, root_cause: str, patterns: dict) -> list:
    pattern_text = ", ".join(f"{k}({v}x)" for k, v in patterns.items()) if patterns else "none"

    prompt = f"""You are a senior cybersecurity analyst AI agent.

Given this incident analysis, provide exactly 5 specific, actionable remediation steps.

Severity: {parsed['severity']}
Root cause: {root_cause}
Recurring patterns in memory: {pattern_text}

Rules:
- Be SPECIFIC to this incident, not generic advice
- Each step must be a single actionable sentence
- Start each line with a number 1-5 and a period
- No markdown, no bold, no extra text

Example format:
1. Block IP 192.168.x.x at the firewall immediately.
2. Rotate all SSH keys on affected servers within 1 hour.
..."""

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
        return recs[:5] if recs else ["Review logs manually and escalate to security team."]
    except Exception as e:
        return [f"Recommendations unavailable: {str(e)}"]

# ── Agent: Step 4 — auto-severity correction via Gemini ──────────────────────
def gemini_verify_severity(parsed: dict, root_cause: str) -> str:
    prompt = f"""Based on this root cause: "{root_cause}"
And these stats: {parsed['errors']} errors, {parsed['warnings']} warnings, score {parsed['score']}/100.

Should the severity be LOW, MEDIUM, HIGH, or CRITICAL?
Respond with ONLY one word: LOW or MEDIUM or HIGH or CRITICAL"""
    try:
        response = model.generate_content(prompt)
        verdict = response.text.strip().upper()
        if verdict in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            return verdict
        return parsed["severity"]
    except:
        return parsed["severity"]

# ── Main agent orchestration ──────────────────────────────────────────────────
def run_agent(content: str) -> dict:
    # Step 1: parse
    parsed = parse_log(content)

    # Step 2: get memory context
    history = get_history()
    patterns = get_recurring_patterns()

    # Step 3: root cause
    root_cause = gemini_root_cause(parsed, parsed["snippet"], history)

    # Step 4: dynamic recommendations
    recommendations = gemini_recommendations(parsed, root_cause, patterns)

    # Step 5: verify severity
    final_severity = gemini_verify_severity(parsed, root_cause)

    result = {
        **parsed,
        "severity": final_severity,
        "root_cause": root_cause,
        "recommendations": recommendations,
        "log_snippet": parsed["snippet"],
        "history": history,
        "patterns": patterns
    }

    # Step 6: save to memory
    save_incident(result)

    return result

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
                result = run_agent(content)
            except Exception as e:
                error_msg = str(e)
        else:
            error_msg = "Please upload a log file."

    history = get_history()
    return render_template('index.html', result=result,
                           history=history, error_msg=error_msg)

@app.route('/history')
def history():
    return jsonify(get_history(20))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
