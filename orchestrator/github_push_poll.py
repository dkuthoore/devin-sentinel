"""Poll default-branch HEAD; start Devin audit when a new push lands on master."""

from __future__ import annotations

import logging

from sqlmodel import Session, select

from orchestrator import github_client
from orchestrator import orchestrator as orch
from orchestrator.config import settings
from orchestrator.database import engine
from orchestrator.events import notify
from orchestrator.models import RepoWatchState, utc_now

logger = logging.getLogger(__name__)


def _get_or_create_watch(db: Session, repo: str, branch: str) -> RepoWatchState:
    watch = db.exec(
        select(RepoWatchState).where(
            RepoWatchState.repo == repo,
            RepoWatchState.branch == branch,
        )
    ).first()
    if watch is None:
        watch = RepoWatchState(repo=repo, branch=branch)
        db.add(watch)
    return watch


def check_default_branch_push() -> bool:
    """
    Compare GitHub default-branch HEAD to the last seen SHA.
    On change (after initial seed), start a Devin audit session.
    Returns True if a new audit was started (or an active audit already exists).
    """
    if not settings.github_push_poll_enabled:
        return False

    branch = settings.github_default_branch
    repo = settings.github_repo

    try:
        current_sha = github_client.get_branch_head_sha(branch)
    except Exception as exc:
        logger.exception("GitHub push poll failed for %s/%s: %s", repo, branch, exc)
        return False

    if not current_sha:
        return False

    audit_started = False
    with Session(engine) as db:
        watch = _get_or_create_watch(db, repo, branch)

        if watch.last_sha is None:
            watch.last_sha = current_sha
            watch.updated_at = utc_now()
            db.add(watch)
            db.commit()
            logger.info(
                "GitHub push poll: seeded %s@%s at %s",
                repo,
                branch,
                current_sha[:7],
            )
            return False

        if watch.last_sha == current_sha:
            return False

        previous = watch.last_sha
        watch.last_sha = current_sha
        watch.updated_at = utc_now()
        db.add(watch)
        db.commit()
        logger.info(
            "GitHub push poll: %s@%s advanced %s -> %s; starting Devin audit",
            repo,
            branch,
            previous[:7],
            current_sha[:7],
        )

    record = orch.start_devin_audit()
    audit_started = record is not None
    if audit_started:
        notify()
    return audit_started
