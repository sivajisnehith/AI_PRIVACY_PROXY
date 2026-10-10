from __future__ import annotations

from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/upload", methods=["POST"])
def upload():
    prompt = request.form.get("prompt", "")
    uploaded_files = request.files.getlist("file")

    print("\n--- TEST SERVER RECEIVED ---")
    print("Files received:", len(uploaded_files))

    return jsonify({
        "received_prompt": prompt,
        "files_received": len(uploaded_files),
        "message": "Local test server received the request."
    })


@app.route("/echo", methods=["GET", "POST"])
def echo():
    """Unrelated endpoint used to verify the proxy leaves other requests untouched."""
    return jsonify({
        "method": request.method,
        "data": request.get_data(as_text=True),
        "args": request.args.to_dict(),
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
