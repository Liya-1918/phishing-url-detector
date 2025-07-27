from flask import Flask, render_template, request
from main import phishing_score


app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    url = ""
    if request.method == "POST":
        url = request.form["url"]
        score, reasons = phishing_score(url)
        result = {
            "url": url,
            "score": score,
            "reasons": reasons
        }
    return render_template("index.html", result=result, url=url)

if __name__ == "__main__":
    app.run(debug=True)
