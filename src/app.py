import base64
import copy
import http
import json
import random
import jsonpatch
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route("/validate", methods=["POST"])
def validate():
    requests.post(url="http://192.168.1.252:5000/api/v1/cluster/1/events",json=json.dumps(request.json))
    allowed = True
    try:
        for container_spec in request.json["request"]["object"]["spec"]["containers"]:
            if "env" in container_spec:
                allowed = False
    except KeyError:
        pass
    return jsonify(
        {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "allowed": allowed,
                "uid": request.json["request"]["uid"],
                "status": {"message": "env keys are prohibited"},
            }
        }
    )


@app.route("/mutate", methods=["POST"])
def mutate():
    spec = request.json["request"]["object"]
    modified_spec = copy.deepcopy(spec)

    try:
        modified_spec["metadata"]["labels"]["example.com/new-label"] = str(
            random.randint(1, 1000)
        )
    except KeyError:
        pass
    patch = jsonpatch.JsonPatch.from_diff(spec, modified_spec)
    return jsonify(
        {
            "response": {
                "allowed": True,
                "uid": request.json["request"]["uid"],
                "patch": base64.b64encode(str(patch).encode()).decode(),
                "patchtype": "JSONPatch",
            }
        }
    )


@app.route("/health", methods=["GET"])
def health():
    return ("", http.HTTPStatus.NO_CONTENT)


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # pragma: no cover
