from sqlmodel import Session, select

from orchestrator import orchestrator
from orchestrator.database import engine
from orchestrator.models import RemediationSession, SessionType

FINDING = {
    "cve_id": "CVE-2026-44307",
    "package": "mako",
    "current_version": "1.3.11",
    "fix_versions": ["1.3.12"],
    "description": "demo finding",
}


def test_dispatch_remediation_is_idempotent_by_cve():
    first = orchestrator.dispatch_remediation(FINDING)
    second = orchestrator.dispatch_remediation(FINDING)

    assert first is not None
    assert second is not None
    assert first.id == second.id

    with Session(engine) as db:
        records = db.exec(
            select(RemediationSession).where(RemediationSession.session_type == SessionType.REMEDIATION)
        ).all()

    assert len(records) == 1
    assert records[0].github_issue_url is not None
    assert records[0].devin_session_id is not None
