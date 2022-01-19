from flask import Flask, jsonify, request
import requests
import os

app = Flask(__name__)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"message":"ok"})

@app.route("/validate", methods=["GET","POST"])
def validate():
    verify = True
    if os.environ.get("IGNORE_CERT") == "yes":
        verify = False
    results = requests.post(
        url=os.environ.get("SERVER_URL"),
        headers={"token":os.environ.get("TOKEN")},
        json=request.json,
        verify=verify
    )
    return jsonify(results.json())

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # pragma: no cover
