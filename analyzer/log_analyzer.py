def analyze_log(content):

    errors = content.count("ERROR")
    warnings = content.count("WARNING")

    score = errors * 5 + warnings * 2

    if score < 10:
        severity = "LOW"
        recommendation = "System stable. Continue monitoring."

    elif score < 20:
        severity = "MEDIUM"
        recommendation = "Review recurring warnings and investigate anomalies."

    elif score < 40:
        severity = "HIGH"
        recommendation = "Immediate investigation recommended."

    else:
        severity = "CRITICAL"
        recommendation = "Urgent incident response required."

    return {
        "errors": errors,
        "warnings": warnings,
        "score": score,
        "severity": severity,
        "recommendation": recommendation
    } 
