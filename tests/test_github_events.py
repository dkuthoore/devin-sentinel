from unittest.mock import patch

from sqlmodel import Session

from orchestrator import github_client
from orchestrator.database import engine
from orchestrator.github_events import issue_numbers_in_pr_body, sync_github_for_record
from orchestrator.models import RemediationSession, SessionStatus, SessionType
from tests import fakes


def test_issue_numbers_in_pr_body_prefers_closes():
    body = "Fixes CVE\n\nCloses #42\n\nAlso mentions #99"
    assert issue_numbers_in_pr_body(body) == [42]


def test_sync_github_promotes_in_progress_to_pr_opened():
    issue = fakes.make_issue(cve_id="CVE-TEST-1", package="mako", number=110)
    pr = fakes.make_pr(issue_number=issue["number"], number=1001)

    with Session(engine) as db:
        session = RemediationSession(
            session_type=SessionType.REMEDIATION,
            status=SessionStatus.IN_PROGRESS,
            cve_id="CVE-TEST-1",
            package="mako",
            github_issue_number=issue["number"],
            github_issue_url=issue["html_url"],
            devin_session_id="devin-remediation-test",
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        with patch.object(github_client, "find_pr_for_issue", return_value=pr):
            assert sync_github_for_record(db, session) is True
        db.refresh(session)
        assert session.status == SessionStatus.PR_OPENED
        assert session.github_pr_number == pr["number"]
