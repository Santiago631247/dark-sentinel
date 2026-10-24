
from flask import Flask, render_template, jsonify
from sentinel import analyze_log

app = Flask(__name__)


@app.route("/")
def dashboard():
    report = analyze_log()
    return render_template("index.html", report=report)


@app.route("/api/status")
def api_status():
    report = analyze_log()

    return jsonify({
        "status": "online",
        "source": report["source"],
        "total_lines": report["total_lines"],
        "failed_attempts": report["failed_attempts"],
        "unique_ips": len(report["ip_counts"]),
        "alerts": report["alerts"],
        "errors": report["errors"],
        "ip_counts": dict(report["ip_counts"]),
        "threshold": 5,
    })


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
