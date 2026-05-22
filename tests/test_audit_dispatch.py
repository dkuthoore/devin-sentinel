import json
from unittest.mock import patch

from sqlmodel import Session, select

from orchestrator import devin_client
from orchestrator import orchestrator as orch
from orchestrator.database import engine
from orchestrator.devin_client import DevinApiError
from orchestrator.models import RemediationSession, SessionStatus, SessionType

AUDIT_DONE_MSG = (
    "AUDIT_DONE: "
    + json.dumps(
        [
            {
                "cve_id": "CVE-2026-10001",
                "package": "werkzeug",
                "current_version": "3.0.0",
                "fix_versions": ["3.0.1"],
                "description": "test",
                "github_issue_url": "https://github.com/example/superset/issues/501",
                "github_issue_number": 501,
            },
            {
                "cve_id": "CVE-2026-10002",
                "package": "jinja2",
                "current_version": "3.0.0",
                "fix_versions": ["3.1.0"],
                "description": "test",
                "github_issue_url": "https://github.com/example/superset/issues/502",
                "github_issue_number": 502,
            },
        ]
    )
)


def test_failed_audit_with_audit_done_reopens_as_issue_created():
    with Session(engine) as db:
        failed = RemediationSession(
            session_type=SessionType.AUDIT,
            status=SessionStatus.FAILED,
            devin_session_id="audit-done-test",
            devin_session_url="https://app.devin.ai/sessions/audit-done-test",
            error_message="quota",
            last_message="old",
        )
        db.add(failed)
        db.commit()

    full_session = {
        "session_id": "audit-done-test",
        "url": "https://app.devin.ai/sessions/audit-done-test",
        "status": "running",
        "title": "Sentinel audit",
        "messages": [AUDIT_DONE_MSG],
        "devin_messages": [AUDIT_DONE_MSG],
    }
    devin_payload = {
        "session_id": "audit-done-test",
        "url": "https://app.devin.ai/sessions/audit-done-test",
        "status": "running",
        "title": "Sentinel audit",
    }

    list_patch = "orchestrator.orchestrator.devin_client.list_active_devin_sessions"
    get_patch = "orchestrator.orchestrator.devin_client.get_session"
    with patch(list_patch, return_value=[devin_payload]):
        with patch(get_patch, return_value=full_session):
            dispatch_patch = "orchestrator.orchestrator.dispatch_audit_findings"
            with patch(dispatch_patch, return_value=(2, 0, 0)) as dispatch:
                orch.reconcile_devin_sessions()

    dispatch.assert_called_once()
    with Session(engine) as db:
        record = db.exec(
            select(RemediationSession).where(
                RemediationSession.devin_session_id == "audit-done-test"
            )
        ).one()
    assert record.status == SessionStatus.ISSUE_CREATED
    assert record.error_message is None
    assert record.completed_at is not None


def test_process_audit_findings_keeps_issue_created_on_dispatch_failure():
    findings = devin_client.parse_audit_done([AUDIT_DONE_MSG])
    assert findings is not None

    with Session(engine) as db:
        audit = RemediationSession(
            session_type=SessionType.AUDIT,
            status=SessionStatus.AUDIT_RUNNING,
            devin_session_id="audit-poll-test",
        )
        db.add(audit)
        db.commit()
        db.refresh(audit)

        quota_error = DevinApiError(
            403,
            "Your organization has a billing error. Error: out_of_quota",
            context="create session",
        )
        with patch(
            "orchestrator.orchestrator.dispatch_remediation",
            side_effect=quota_error,
        ):
            orch.process_audit_findings(db, audit, findings)
        db.refresh(audit)

        assert audit.status == SessionStatus.ISSUE_CREATED
        assert audit.error_message is not None
        assert "failed" in audit.error_message.lower()
        assert "out_of_quota" in audit.error_message

        remediations = db.exec(
            select(RemediationSession).where(
                RemediationSession.session_type == SessionType.REMEDIATION
            )
        ).all()
        assert len(remediations) == 2
        assert all(row.status == SessionStatus.FAILED for row in remediations)
        assert all(row.error_message and "out_of_quota" in row.error_message for row in remediations)


def test_dispatch_audit_findings_is_idempotent_per_cve():
    findings = devin_client.parse_audit_done([AUDIT_DONE_MSG])
    assert findings is not None

    with patch("orchestrator.orchestrator.dispatch_remediation") as dispatch:
        dispatch.side_effect = [
            RemediationSession(
                session_type=SessionType.REMEDIATION,
                status=SessionStatus.IN_PROGRESS,
                cve_id="CVE-2026-10001",
            ),
            RemediationSession(
                session_type=SessionType.REMEDIATION,
                status=SessionStatus.IN_PROGRESS,
                cve_id="CVE-2026-10002",
            ),
        ]
        first = orch.dispatch_audit_findings(findings)
        assert first == (2, 0, 0)
        assert dispatch.call_count == 2

        dispatch.reset_mock()
        with Session(engine) as db:
            for finding in findings:
                db.add(
                    RemediationSession(
                        session_type=SessionType.REMEDIATION,
                        status=SessionStatus.IN_PROGRESS,
                        cve_id=finding.cve_id,
                        package=finding.package,
                    )
                )
            db.commit()

        second = orch.dispatch_audit_findings(findings)
        assert second == (0, 2, 0)
        dispatch.assert_not_called()
