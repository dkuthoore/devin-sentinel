from unittest.mock import patch

from sqlmodel import Session, select

from orchestrator import orchestrator as orch
from orchestrator.database import engine
from orchestrator.models import RemediationSession, SessionStatus, SessionType


def test_reconcile_creates_missing_row():
    devin_payload = {
        "session_id": "abc123",
        "url": "https://app.devin.ai/sessions/abc123",
        "status": "running",
        "title": "Sentinel audit",
    }
    full_session = {
        **devin_payload,
        "messages": [],
        "devin_messages": ["Working..."],
        "status": "running",
    }

    list_patch = "orchestrator.orchestrator.devin_client.list_active_devin_sessions"
    get_patch = "orchestrator.orchestrator.devin_client.get_session"
    with patch(list_patch, return_value=[devin_payload]):
        with patch(get_patch, return_value=full_session):
            records = orch.reconcile_devin_sessions()

    assert len(records) == 1
    assert records[0].devin_session_id == "abc123"
    assert records[0].status == SessionStatus.AUDIT_RUNNING
    assert records[0].session_type == SessionType.AUDIT


def test_reconcile_reopens_failed_row():
    with Session(engine) as db:
        failed = RemediationSession(
            session_type=SessionType.AUDIT,
            status=SessionStatus.FAILED,
            devin_session_id="6e3d39f809a743ce8befc9e2c5f81d5b",
            devin_session_url="https://app.devin.ai/sessions/6e3d39f809a743ce8befc9e2c5f81d5b",
            error_message="<reason>",
            last_message="old",
        )
        db.add(failed)
        db.commit()

    devin_payload = {
        "session_id": "6e3d39f809a743ce8befc9e2c5f81d5b",
        "url": "https://app.devin.ai/sessions/6e3d39f809a743ce8befc9e2c5f81d5b",
        "status": "running",
        "title": "Sentinel audit",
    }
    full_session = {**devin_payload, "messages": [], "devin_messages": ["Still working"], "status": "running"}

    list_patch = "orchestrator.orchestrator.devin_client.list_active_devin_sessions"
    get_patch = "orchestrator.orchestrator.devin_client.get_session"
    with patch(list_patch, return_value=[devin_payload]):
        with patch(get_patch, return_value=full_session):
            records = orch.reconcile_devin_sessions("6e3d39f809a743ce8befc9e2c5f81d5b")

    assert len(records) == 1
    assert records[0].status == SessionStatus.AUDIT_RUNNING
    assert records[0].error_message is None
    assert records[0].completed_at is None

    with Session(engine) as db:
        stored = db.exec(select(RemediationSession)).all()
        assert len(stored) == 1
        assert stored[0].status == SessionStatus.AUDIT_RUNNING
