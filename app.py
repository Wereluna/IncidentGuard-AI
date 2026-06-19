from flask import Flask, render_template, request
from analyzer.log_analyzer import analyze_log

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":

        file = request.files["logfile"]

        if file:
            content = file.read().decode("utf-8")

            result = analyze_log(content)

    return render_template(
        "index.html",
        result=result
    )

import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
