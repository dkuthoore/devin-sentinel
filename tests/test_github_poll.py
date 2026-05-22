import asyncio
from unittest.mock import patch

from sqlmodel import Session, select

from orchestrator import github_client, orchestrator
from orchestrator.database import engine
from orchestrator.models import RemediationSession
from orchestrator.poller import poll_once
from tests import fakes

FINDING = {
    "cve_id": "CVE-2026-POLL-1",
    "package": "werkzeug",
    "current_version": "3.0.0",
    "fix_versions": ["3.0.1"],
    "description": "poll test",
}


def test_poller_finds_pr_before_devin_done():
    record = orchestrator.dispatch_remediation(FINDING)
    assert record is not None
    assert record.github_issue_number is not None

    pr = fakes.make_pr(
        issue_number=record.github_issue_number,
        number=4242,
        url="https://github.com/example/superset/pull/4242",
    )

    with patch.object(github_client, "find_pr_for_issue", return_value=pr):
        asyncio.run(poll_once())

    with Session(engine) as db:
        refreshed = db.exec(
            select(RemediationSession).where(RemediationSession.id == record.id)
        ).one()

    assert refreshed.status.value == "pr_opened"
    assert refreshed.github_pr_number == pr["number"]
