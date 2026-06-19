def analyze_log(content):
    errors = content.count("ERROR")
    warnings = content.count("WARNING")

    return f"Errors: {errors}, Warnings: {warnings}"
