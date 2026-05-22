import asyncio

from fastapi.testclient import TestClient

from orchestrator.main import app
from orchestrator.poller import poll_once
from tests import fakes


def test_devin_scan_endpoint_creates_audit_and_remediation_sessions():
    with TestClient(app) as client:
        response = client.post("/scan/devin")
        assert response.status_code == 200

        fakes.advance_session(fakes.AUDIT_SESSION_ID)
        asyncio.run(poll_once())

        for session_id in fakes.REMEDIATION_SESSION_IDS:
            fakes.advance_session(session_id)
        asyncio.run(poll_once())

        sessions = client.get("/sessions").json()
        metrics = client.get("/metrics").json()

    assert len(sessions) == 4
    assert metrics["audit_sessions"] == 1
    assert metrics["remediation_sessions"] == 3
    assert metrics["prs_opened"] == 3


def test_dashboard_serves_html():
    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert "Sentinel" in response.text
    assert "Mock mode" not in response.text
