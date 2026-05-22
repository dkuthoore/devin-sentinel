import asyncio
import logging
import time
from datetime import UTC, timedelta
from urllib.parse import urlparse

from sqlmodel import Session, select

from orchestrator import devin_client, github_client
from orchestrator import orchestrator as orch
from orchestrator.config import settings
from orchestrator.database import engine
from orchestrator.devin_client import DevinApiError
from orchestrator.events import notify
from orchestrator.github_events import sync_github_for_record
from orchestrator.github_push_poll import check_default_branch_push
from orchestrator.models import RemediationSession, SessionStatus, SessionType, utc_now

logger = logging.getLogger(__name__)

_last_reconcile_at: float = 0.0

_ACTIVE_POLL_STATUSES = (
    SessionStatus.AUDIT_RUNNING,
    SessionStatus.IN_PROGRESS,
    SessionStatus.PR_OPENED,
)


def _terminal_status(status: SessionStatus) -> bool:
    return status in {
        SessionStatus.ISSUE_CREATED,
        SessionStatus.PR_OPENED,
        SessionStatus.MERGED,
        SessionStatus.FAILED,
    }


def _as_utc_aware(moment):
    if moment.tzinfo is None:
        return moment.replace(tzinfo=UTC)
    return moment.astimezone(UTC)


def _record_outside_lookback(record: RemediationSession) -> bool:
    hours = max(1, settings.devin_session_lookback_hours)
    cutoff = utc_now() - timedelta(hours=hours)
    return _as_utc_aware(record.created_at) < _as_utc_aware(cutoff)


def _pr_number_from_url(url: str) -> int | None:
    try:
        path = urlparse(url).path.rstrip("/")
        return int(path.split("/")[-1])
    except (ValueError, IndexError):
        return None


def _apply_pr_from_done(record: RemediationSession, pr_url: str) -> None:
    record.github_pr_url = pr_url
    record.github_pr_number = _pr_number_from_url(pr_url)
    pr = None
    if record.github_issue_number:
        pr = github_client.find_pr_for_issue(record.github_issue_number)
    record.status = SessionStatus.MERGED if pr and pr.get("merged_at") else SessionStatus.PR_OPENED
    record.updated_at = utc_now()
    record.completed_at = utc_now()


async def poll_once() -> None:
    global _last_reconcile_at
    if settings.github_push_poll_enabled:
        try:
            await asyncio.to_thread(check_default_branch_push)
        except Exception as exc:
            logger.exception("GitHub push poll failed: %s", exc)

    now = time.monotonic()
    if now - _last_reconcile_at >= settings.devin_reconcile_interval_seconds:
        try:
            await asyncio.to_thread(orch.reconcile_devin_sessions)
            notify()
        except Exception as exc:
            logger.exception("Devin reconcile failed: %s", exc)
        _last_reconcile_at = now

    with Session(engine) as db:
        records = db.exec(
            select(RemediationSession).where(RemediationSession.status.in_(_ACTIVE_POLL_STATUSES))
        ).all()

        for record in records:
            try:
                await poll_record(db, record)
            except DevinApiError as exc:
                logger.error("Polling failed for record %s: %s", record.id, exc.user_message())
                orch.mark_record_failed(db, record, exc.user_message())
                notify()
            except Exception as exc:
                logger.exception("Polling failed for record %s: %s", record.id, exc)
                orch.mark_record_failed(db, record, str(exc))
                notify()


async def poll_record(db: Session, record: RemediationSession) -> None:
    if record.status in {SessionStatus.AUDIT_RUNNING, SessionStatus.IN_PROGRESS} and _record_outside_lookback(
        record
    ):
        orch.mark_record_failed(
            db,
            record,
            f"Session older than {settings.devin_session_lookback_hours}h lookback; not polled.",
        )
        return

    if record.status == SessionStatus.PR_OPENED:
        if sync_github_for_record(db, record):
            return
        record.updated_at = utc_now()
        db.add(record)
        db.commit()
        return

    if not record.devin_session_id or _terminal_status(record.status):
        return

    if record.session_type == SessionType.REMEDIATION and sync_github_for_record(db, record):
        return

    session_data = await asyncio.to_thread(devin_client.get_session, record.devin_session_id)
    messages = devin_client.extract_messages(session_data)
    sentinel_messages = devin_client.extract_sentinel_messages(session_data)
    if sentinel_messages:
        record.last_message = sentinel_messages[-1]
    elif messages:
        record.last_message = messages[-1]

    blocked_reason = devin_client.parse_blocked_reason(sentinel_messages)
    if blocked_reason:
        record.status = SessionStatus.FAILED
        record.error_message = blocked_reason
        record.updated_at = utc_now()
        record.completed_at = utc_now()
        db.add(record)
        db.commit()
        notify()
        return

    if record.session_type == SessionType.AUDIT:
        findings = devin_client.parse_audit_done(sentinel_messages)
        if findings is None:
            record.updated_at = utc_now()
            db.add(record)
            db.commit()
            return

        await asyncio.to_thread(orch.process_audit_findings, db, record, findings)
        return

    if sync_github_for_record(db, record):
        return

    pr_url = devin_client.parse_done_pr_url(sentinel_messages)
    if not pr_url:
        record.updated_at = utc_now()
        db.add(record)
        db.commit()
        return

    _apply_pr_from_done(record, pr_url)
    db.add(record)
    db.commit()
    notify()


async def polling_loop(interval_seconds: int) -> None:
    logger.info("Poller started with %s second interval", interval_seconds)
    while True:
        await poll_once()
        await asyncio.sleep(interval_seconds)
