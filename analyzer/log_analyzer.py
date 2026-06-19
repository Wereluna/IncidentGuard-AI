def analyze_log(content):

    errors = content.count("ERROR")
    warnings = content.count("WARNING")

    if errors >= 10:
        severity = "HIGH"
    elif errors >= 5:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return f"""
Errors Found: {errors}

Warnings Found: {warnings}

Severity Level: {severity}
"""
