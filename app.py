from flask import Flask, render_template, request
#from analyzer.log_analyzer import analyze_log

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def home():

    if request.method == 'POST':

        file = request.files['logfile']

        if file:

            content = file.read().decode('utf-8')

            errors = content.count("ERROR")
            warnings = content.count("WARNING")

            score = errors * 10 + warnings * 5

            if score < 20:
                severity = "LOW"
            elif score < 50:
                severity = "MEDIUM"
            elif score < 80:
                severity = "HIGH"
            else:
                severity = "CRITICAL"

            return render_template(
                "index.html",
                errors=errors,
                warnings=warnings,
                score=score,
                severity=severity
            )

    return render_template(
        "index.html",
        errors=0,
        warnings=0,
        score=0,
        severity="LOW"
    )
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port) 
