import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def app_client():
    import app as app_module
    app_module.app.config["TESTING"] = True
    app_module.app.config["SECRET_KEY"] = "test"
    with app_module.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["authenticated"] = True
        yield client, app_module


def test_requirements_status_endpoint_lists_requirements(app_client):
    client, _ = app_client

    resp = client.get("/api/requirements/status")

    assert resp.status_code == 200
    data = resp.get_json()
    assert "items" in data
    assert "missing" in data
    assert "missing_count" in data
    assert "installable_missing_count" in data
    assert any(item["id"] == "python-requests" for item in data["items"])
    assert any(item["id"] == "tool-sqlmap" for item in data["items"])


def test_requirements_install_dry_run_does_not_execute_commands(app_client, monkeypatch):
    client, app_module = app_client
    executed = []

    monkeypatch.setattr(app_module, "_requirements_status_items", lambda: [
        {
            "id": "python-requests",
            "name": "requests",
            "category": "Python package",
            "available": False,
            "required": True,
            "installable": True,
            "install_command": "python -m pip install -r requirements.txt",
            "install_commands": [["python", "-m", "pip", "install", "-r", "requirements.txt"]],
            "note": "Installed from requirements.txt",
        }
    ])
    monkeypatch.setattr(app_module.subprocess, "run", lambda *args, **kwargs: executed.append((args, kwargs)))

    resp = client.post("/api/requirements/install", json={"dry_run": True})

    assert resp.status_code == 200
    data = resp.get_json()
    assert data["status"] == "dry_run"
    assert data["command_count"] == 1
    assert executed == []

