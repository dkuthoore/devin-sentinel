import asyncio

from sqlmodel import Session, select

from orchestrator.config import settings
from orchestrator.database import engine
from orchestrator.github_push_poll import check_default_branch_push
from orchestrator.models import RemediationSession, RepoWatchState, SessionStatus, SessionType
from orchestrator.poller import poll_once
from tests import fakes


def test_push_poll_seeds_without_audit():
    assert check_default_branch_push() is False
    with Session(engine) as db:
        watch = db.exec(
            select(RepoWatchState).where(
                RepoWatchState.repo == settings.github_repo,
                RepoWatchState.branch == settings.github_default_branch,
            )
        ).first()
        assert watch is not None
        assert watch.last_sha == "sha-initial-seed"
        audits = db.exec(
            select(RemediationSession).where(RemediationSession.session_type == SessionType.AUDIT)
        ).all()
        assert len(audits) == 0


def test_push_poll_triggers_audit_on_new_sha():
    check_default_branch_push()
    fakes.set_branch_head(settings.github_default_branch, "sha-after-push")

    assert check_default_branch_push() is True

    with Session(engine) as db:
        audits = db.exec(
            select(RemediationSession).where(RemediationSession.session_type == SessionType.AUDIT)
        ).all()
    assert len(audits) == 1
    assert audits[0].status == SessionStatus.AUDIT_RUNNING


def test_push_poll_dedupes_active_audit():
    check_default_branch_push()
    fakes.set_branch_head(settings.github_default_branch, "sha-2")
    check_default_branch_push()

    fakes.set_branch_head(settings.github_default_branch, "sha-3")
    check_default_branch_push()

    with Session(engine) as db:
        audits = db.exec(
            select(RemediationSession).where(RemediationSession.session_type == SessionType.AUDIT)
        ).all()
    assert len(audits) == 1


def test_poll_once_runs_push_poll_integration():
    fakes.set_branch_head(settings.github_default_branch, "sha-demo")
    asyncio.run(poll_once())
    fakes.set_branch_head(settings.github_default_branch, "sha-demo-2")
    asyncio.run(poll_once())

    with Session(engine) as db:
        audits = db.exec(
            select(RemediationSession).where(RemediationSession.session_type == SessionType.AUDIT)
        ).all()
    assert len(audits) == 1
