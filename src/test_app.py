import pytest
from flask import url_for

def valid(response):
    return {"uid", "allowed"} <= response.json["response"].keys()

class TestHeathcheck(object):
    def test_healthcheck(self, client):
        assert client.get(url_for("health")).status_code == 204
