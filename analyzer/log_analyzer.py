def analyze_log(content):
    errors = content.count("ERROR")
    warnings = content.count("WARNING")

    score = errors * 5 + warnings * 2

    if score < 10:
        severity = "LOW"
    elif score < 20:
        severity = "MEDIUM"
    elif score < 40:
        severity = "HIGH"
    else:
        severity = "CRITICAL"

    return {
        "errors": errors,
        "warnings": warnings,
        "severity": severity
    }
