import asyncio
import json
import logging
import multiprocessing
import os
import signal
import sys
from contextlib import asynccontextmanager

import click
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlmodel import Session, select

from orchestrator import orchestrator as orch
from orchestrator.config import ConfigurationError, settings, validate_required_settings
from orchestrator.database import create_db, get_session
from orchestrator.events import subscribe
from orchestrator.models import (
    Metrics,
    RemediationSession,
    SessionStatus,
    SessionSyncRequest,
    SessionSyncResponse,
    SessionType,
)
from orchestrator.poller import polling_loop

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def _ensure_required_settings() -> None:
    """Exit the process (and uvicorn --reload parent) when required env vars are missing."""
    try:
        validate_required_settings()
    except ConfigurationError as exc:
        for line in str(exc).splitlines():
            click.echo(click.style(line, fg="red"), err=True)
        parent = multiprocessing.parent_process()
        if parent is not None:
            try:
                os.kill(parent.pid, signal.SIGTERM)
            except OSError:
                pass
        sys.exit(1)


_ensure_required_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db()
    try:
        synced = await asyncio.to_thread(orch.reconcile_devin_sessions)
        logger.info("Startup Devin reconcile synced %s session(s)", len(synced))
    except Exception as exc:
        logger.exception("Startup Devin reconcile failed: %s", exc)
    task = asyncio.create_task(polling_loop(settings.poll_interval_seconds))
    if settings.github_push_poll_enabled:
        logger.info(
            "GitHub push poll enabled for %s@%s",
            settings.github_repo,
            settings.github_default_branch,
        )
    logger.info("Sentinel started")
    try:
        yield
    finally:
        task.cancel()
        logger.info("Sentinel stopped")


app = FastAPI(
    title="Sentinel CVE Remediation",
    description="Automated CVE triage and remediation using Devin and GitHub.",
    version="0.1.0",
    lifespan=lifespan,
)


def _run_devin_audit_background() -> None:
    orch.start_devin_audit()


@app.post("/scan")
def trigger_scan(background_tasks: BackgroundTasks) -> dict[str, str]:
    """Start a Devin audit session (same as POST /scan/devin)."""
    background_tasks.add_task(_run_devin_audit_background)
    return {"status": "devin audit started"}


@app.post("/scan/devin")
def trigger_devin_scan(background_tasks: BackgroundTasks) -> dict[str, str]:
    background_tasks.add_task(_run_devin_audit_background)
    return {"status": "devin audit started"}


@app.post("/sessions/sync", response_model=SessionSyncResponse)
def sync_devin_sessions(
    body: SessionSyncRequest | None = None,
) -> SessionSyncResponse:
    """Discover active Devin v3 sessions and upsert/reopen DB rows (API/debug; UI uses background sync)."""
    devin_session_id = body.devin_session_id if body else None
    records = orch.reconcile_devin_sessions(devin_session_id)
    return SessionSyncResponse(synced=len(records))


@app.get("/events")
async def events_stream() -> StreamingResponse:
    """Server-Sent Events stream for live dashboard updates."""

    async def event_generator():
        yield f"data: {json.dumps({'type': 'connected'})}\n\n"
        async for event in subscribe():
            yield f"data: {json.dumps(event)}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/sessions", response_model=list[RemediationSession])
def list_sessions(db: Session = Depends(get_session)) -> list[RemediationSession]:
    return db.exec(select(RemediationSession).order_by(RemediationSession.created_at.desc())).all()


@app.get("/sessions/{session_id}", response_model=RemediationSession)
def get_session_detail(session_id: int, db: Session = Depends(get_session)) -> RemediationSession:
    record = db.get(RemediationSession, session_id)
    if not record:
        raise HTTPException(status_code=404, detail="Session not found")
    return record


@app.get("/metrics", response_model=Metrics)
def get_metrics(db: Session = Depends(get_session)) -> Metrics:
    sessions = db.exec(select(RemediationSession)).all()
    remediation = [session for session in sessions if session.session_type == SessionType.REMEDIATION]
    by_status: dict[str, int] = {}
    for session in sessions:
        by_status[session.status.value] = by_status.get(session.status.value, 0) + 1

    completed = [
        session
        for session in remediation
        if session.completed_at
        and session.created_at
        and session.status in {SessionStatus.PR_OPENED, SessionStatus.MERGED}
    ]
    avg_resolution_minutes = None
    if completed:
        durations = [
            (session.completed_at - session.created_at).total_seconds() / 60
            for session in completed
        ]
        avg_resolution_minutes = round(sum(durations) / len(durations), 1)

    packages = sorted({session.package for session in remediation if session.package})
    return Metrics(
        total_cves_detected=len({session.cve_id for session in remediation if session.cve_id}),
        audit_sessions=len([session for session in sessions if session.session_type == SessionType.AUDIT]),
        remediation_sessions=len(remediation),
        issues_created=len([session for session in sessions if session.github_issue_url]),
        devin_sessions=len([session for session in sessions if session.devin_session_id]),
        prs_opened=len([session for session in remediation if session.github_pr_url]),
        merged=len([session for session in remediation if session.status == SessionStatus.MERGED]),
        failed=len([session for session in sessions if session.status == SessionStatus.FAILED]),
        by_status=by_status,
        avg_resolution_minutes=avg_resolution_minutes,
        packages_affected=packages,
    )


@app.get("/", response_class=HTMLResponse)
def dashboard() -> str:
    dashboard_file = settings.dashboard_path
    if not dashboard_file.exists():
        raise HTTPException(status_code=404, detail="Dashboard file not found")
    return dashboard_file.read_text(encoding="utf-8")
