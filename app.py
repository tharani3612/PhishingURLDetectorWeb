# app.py
from flask import Flask, render_template, request, redirect, url_for, flash
from phishing_detector import score_url, classify
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"txt"}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.secret_key = "replace-with-a-secure-key"  # change for production

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            score, reasons, features = score_url(url)
            label = classify(score)
            result = {
                "url": url,
                "score": score,
                "label": label,
                "reasons": reasons,
                "features": features
            }
        else:
            flash("Please enter a URL to check.", "warning")
    return render_template("index.html", result=result)

@app.route("/batch", methods=["GET", "POST"])
def batch():
    results = []
    if request.method == "POST":
        if "file" not in request.files:
            flash("No file part in the request.", "danger")
            return redirect(url_for("batch"))
        file = request.files["file"]
        if file.filename == "":
            flash("No file selected.", "warning")
            return redirect(url_for("batch"))
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    url = line.strip()
                    if not url:
                        continue
                    score, reasons, features = score_url(url)
                    label = classify(score)
                    results.append({
                        "url": url,
                        "score": score,
                        "label": label,
                        "reasons": reasons
                    })
            # optionally remove uploaded file
            os.remove(path)
        else:
            flash("Invalid file. Please upload a .txt file with one URL per line.", "danger")
    return render_template("results.html", results=results)

if __name__ == "__main__":
    # development server — in production use proper WSGI server
    app.run(host="127.0.0.1", port=5000, debug=True)
