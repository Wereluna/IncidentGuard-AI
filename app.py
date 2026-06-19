from flask import Flask, render_template, request
from analyzer.log_analyzer import analyze_log

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def home():
    analysis = None

    if request.method == "POST":
        file = request.files["logfile"]

        if file:
            content = file.read().decode("utf-8")
            analysis = analyze_log(content)

    return render_template("index.html", result=analysis)

if __name__ == "__main__":
    app.run(debug=True)
