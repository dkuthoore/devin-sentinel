import logging

from sqlmodel import Session, select

from orchestrator import devin_client, github_client
from orchestrator.database import engine
from orchestrator.devin_client import DevinApiError
from orchestrator.events import notify
from orchestrator.models import CveFinding, RemediationSession, SessionStatus, SessionType, utc_now

logger = logging.getLogger(__name__)


def _finding_from_dict(data: dict) -> CveFinding:
    return CveFinding.model_validate(data)


def _record_for_cve(db: Session, cve_id: str) -> RemediationSession | None:
    return db.exec(
        select(RemediationSession).where(
            RemediationSession.session_type == SessionType.REMEDIATION,
            RemediationSession.cve_id == cve_id,
        )
    ).first()


def _record_for_devin_id(db: Session, devin_session_id: str) -> RemediationSession | None:
    bare = devin_client.bare_devin_id(devin_session_id)
    candidates = {bare, devin_client._ensure_devin_id(bare)}
    records = db.exec(
        select(RemediationSession).where(RemediationSession.devin_session_id.in_(candidates))
    ).all()
    return records[0] if records else None


def _sentinel_status_for_type(session_type: SessionType) -> SessionStatus:
    if session_type == SessionType.AUDIT:
        return SessionStatus.AUDIT_RUNNING
    return SessionStatus.IN_PROGRESS


def _reopenable_sentinel_statuses() -> set[SessionStatus]:
    return {SessionStatus.FAILED, SessionStatus.PENDING}


def _status_after_reconcile(
    record: RemediationSession | None,
    session_type: SessionType,
    session_data: dict,
) -> SessionStatus:
    """Pick DB status when (re)linking a Devin session; respect completed audits."""
    sentinel_messages = devin_client.extract_sentinel_messages(session_data)
    if session_type == SessionType.AUDIT and devin_client.parse_audit_done(sentinel_messages) is not None:
        return SessionStatus.ISSUE_CREATED
    if record and record.session_type == SessionType.AUDIT and record.status == SessionStatus.ISSUE_CREATED:
        return SessionStatus.ISSUE_CREATED
    return _sentinel_status_for_type(session_type)


def _apply_devin_snapshot(record: RemediationSession, session_data: dict) -> None:
    session_id = session_data.get("session_id") or ""
    record.devin_session_id = devin_client.bare_devin_id(str(session_id))
    record.devin_session_url = session_data.get("url") or record.devin_session_url
    sentinel_messages = devin_client.extract_sentinel_messages(session_data)
    if sentinel_messages:
        record.last_message = sentinel_messages[-1]
    record.updated_at = utc_now()


def reconcile_devin_sessions(devin_session_id: str | None = None) -> list[RemediationSession]:
    """
    Discover active Devin v3 sessions and upsert/reopen rows in SQLite.
    Docs: https://docs.devin.ai/api-reference/v3/sessions/organizations-sessions
    """
    active_sessions = devin_client.list_active_devin_sessions(devin_session_id)
    if not active_sessions:
        logger.info("Devin reconcile: no active sessions found")
        return []

    reconciled: list[RemediationSession] = []
    backfill_dispatches: list[tuple[RemediationSession, list[CveFinding]]] = []
    with Session(engine) as db:
        for session_data in active_sessions:
            bare_id = devin_client.bare_devin_id(str(session_data.get("session_id") or ""))
            if not bare_id:
                continue

            full_data = devin_client.get_session(bare_id)
            session_type = devin_client.infer_session_type(full_data)

            record = _record_for_devin_id(db, bare_id)
            target_status = _status_after_reconcile(record, session_type, full_data)

            if record is None:
                record = RemediationSession(
                    session_type=session_type,
                    status=target_status,
                    devin_session_id=bare_id,
                    devin_session_url=full_data.get("url"),
                    last_message="Reconciled from Devin API.",
                    completed_at=utc_now() if target_status == SessionStatus.ISSUE_CREATED else None,
                )
                db.add(record)
                logger.info("Devin reconcile: created DB row for %s", bare_id)
            elif record.status in _reopenable_sentinel_statuses():
                previous_status = record.status
                record.session_type = session_type
                record.status = target_status
                record.error_message = None
                if target_status == SessionStatus.ISSUE_CREATED:
                    record.completed_at = utc_now()
                    logger.info(
                        "Devin reconcile: audit %s already has AUDIT_DONE (was %s) -> issue_created",
                        bare_id,
                        previous_status,
                    )
                else:
                    record.completed_at = None
                    logger.info("Devin reconcile: reopened %s (was %s)", bare_id, previous_status)
            elif record.status in {SessionStatus.AUDIT_RUNNING, SessionStatus.IN_PROGRESS}:
                pass
            else:
                # e.g. issue_created — leave terminal Sentinel state; still refresh links/messages.
                pass

            _apply_devin_snapshot(record, full_data)
            db.add(record)
            reconciled.append(record)

            if record.session_type == SessionType.AUDIT and record.status == SessionStatus.ISSUE_CREATED:
                findings = devin_client.parse_audit_done(
                    devin_client.extract_sentinel_messages(full_data)
                )
                if findings:
                    backfill_dispatches.append((record, findings))

        db.commit()
        for record in reconciled:
            db.refresh(record)

        for audit_record, findings in backfill_dispatches:
            dispatched, skipped, failed = dispatch_audit_findings(findings)
            _apply_audit_dispatch_summary(audit_record, len(findings), dispatched, skipped, failed)
            db.add(audit_record)
        if backfill_dispatches:
            db.commit()
            notify()

    if reconciled:
        notify()

    logger.info("Devin reconcile: synced %s session(s)", len(reconciled))
    return reconciled


def _active_audit_record(db: Session) -> RemediationSession | None:
    return db.exec(
        select(RemediationSession).where(
            RemediationSession.session_type == SessionType.AUDIT,
            RemediationSession.status.in_([SessionStatus.PENDING, SessionStatus.AUDIT_RUNNING]),
        )
    ).first()


def start_devin_audit() -> RemediationSession:
    with Session(engine) as db:
        existing = _active_audit_record(db)
        if existing:
            return existing

        prompt = devin_client.build_audit_prompt()
        try:
            session_data = devin_client.create_session(prompt, SessionType.AUDIT)
        except DevinApiError as exc:
            record = RemediationSession(
                session_type=SessionType.AUDIT,
                status=SessionStatus.FAILED,
                error_message=exc.user_message(),
                last_message=exc.user_message(),
                completed_at=utc_now(),
            )
            db.add(record)
            db.commit()
            db.refresh(record)
            notify()
            return record

        record = RemediationSession(
            session_type=SessionType.AUDIT,
            status=SessionStatus.AUDIT_RUNNING,
            devin_session_id=session_data["session_id"],
            devin_session_url=session_data.get("url"),
            last_message="Devin audit session started.",
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        notify()
        return record


def dispatch_remediation(finding_data: dict | CveFinding) -> RemediationSession | None:
    finding = finding_data if isinstance(finding_data, CveFinding) else _finding_from_dict(finding_data)
    fix_version = finding.fix_version
    if not fix_version:
        logger.warning("Skipping %s: no fix version available", finding.cve_id)
        return None

    with Session(engine) as db:
        existing = _record_for_cve(db, finding.cve_id)
        if existing:
            return existing

        issue_number = finding.github_issue_number
        issue_url = finding.github_issue_url
        if not issue_number or not issue_url:
            existing_issue = github_client.find_issue_by_cve(finding.cve_id)
            if existing_issue:
                issue_number = existing_issue["number"]
                issue_url = existing_issue["html_url"]
            else:
                issue = github_client.create_issue(
                    cve_id=finding.cve_id,
                    package=finding.package,
                    current_version=finding.current_version,
                    fix_version=fix_version,
                    description=finding.description,
                )
                issue_number = issue["number"]
                issue_url = issue["html_url"]

        normalized = finding.model_copy(
            update={"github_issue_number": issue_number, "github_issue_url": issue_url}
        )
        prompt = devin_client.build_remediation_prompt(normalized)
        session_data = devin_client.create_session(prompt, SessionType.REMEDIATION)

        record = RemediationSession(
            session_type=SessionType.REMEDIATION,
            status=SessionStatus.IN_PROGRESS,
            cve_id=finding.cve_id,
            package=finding.package,
            current_version=finding.current_version,
            fix_version=fix_version,
            description=finding.description,
            github_issue_number=issue_number,
            github_issue_url=issue_url,
            devin_session_id=session_data["session_id"],
            devin_session_url=session_data.get("url"),
            last_message="Devin remediation session started.",
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        notify()
        return record


def _audit_dispatch_error_message(failed: int, dispatched: int, sample_error: str | None) -> str:
    if failed <= 0:
        return ""
    base = f"{failed} remediation(s) failed to start"
    if dispatched:
        base = f"{base} ({dispatched} started successfully)"
    if sample_error:
        return f"{base}: {sample_error}"
    return base


def _apply_audit_dispatch_summary(
    record: RemediationSession,
    finding_count: int,
    dispatched: int,
    skipped: int,
    failed: int,
) -> None:
    record.last_message = (
        f"AUDIT_DONE: {finding_count} finding(s); "
        f"remediation dispatched={dispatched} existing={skipped} failed={failed}"
    )
    if failed:
        sample = None
        with Session(engine) as db:
            failed_row = db.exec(
                select(RemediationSession)
                .where(
                    RemediationSession.session_type == SessionType.REMEDIATION,
                    RemediationSession.status == SessionStatus.FAILED,
                )
                .order_by(RemediationSession.updated_at.desc())
            ).first()
            if failed_row and failed_row.error_message:
                sample = failed_row.error_message
        record.error_message = _audit_dispatch_error_message(failed, dispatched, sample)
    else:
        record.error_message = None
    record.updated_at = utc_now()


def _persist_failed_remediation(
    finding: CveFinding,
    error_message: str,
    *,
    issue_number: int | None = None,
    issue_url: str | None = None,
) -> RemediationSession:
    fix_version = finding.fix_version
    with Session(engine) as db:
        existing = _record_for_cve(db, finding.cve_id)
        if existing:
            if existing.status == SessionStatus.FAILED:
                existing.error_message = error_message
                existing.last_message = error_message
                existing.updated_at = utc_now()
                db.add(existing)
                db.commit()
                db.refresh(existing)
                notify()
            return existing

        record = RemediationSession(
            session_type=SessionType.REMEDIATION,
            status=SessionStatus.FAILED,
            cve_id=finding.cve_id,
            package=finding.package,
            current_version=finding.current_version,
            fix_version=fix_version,
            description=finding.description,
            github_issue_number=issue_number or finding.github_issue_number,
            github_issue_url=issue_url or finding.github_issue_url,
            error_message=error_message,
            last_message=error_message,
            completed_at=utc_now(),
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        notify()
        return record


def dispatch_audit_findings(findings: list[CveFinding]) -> tuple[int, int, int]:
    """
    Create remediation sessions for audit findings (idempotent per CVE).
    Returns (dispatched, skipped_existing, failed).
    """
    dispatched = 0
    skipped = 0
    failed = 0

    for finding in findings:
        with Session(engine) as db:
            if _record_for_cve(db, finding.cve_id):
                skipped += 1
                continue

        try:
            if dispatch_remediation(finding):
                dispatched += 1
        except DevinApiError as exc:
            failed += 1
            _persist_failed_remediation(finding, exc.user_message())
            logger.error(
                "Remediation dispatch failed for %s: %s",
                finding.cve_id,
                exc.user_message(),
            )
        except Exception as exc:
            failed += 1
            message = str(exc)
            _persist_failed_remediation(finding, message)
            logger.exception(
                "Remediation dispatch failed for %s: %s",
                finding.cve_id,
                exc,
            )

    if dispatched or failed:
        logger.info(
            "Audit findings dispatch: %s new, %s existing, %s failed",
            dispatched,
            skipped,
            failed,
        )
    return dispatched, skipped, failed


def process_audit_findings(db: Session, record: RemediationSession, findings: list[CveFinding]) -> None:
    """Mark audit complete and dispatch remediations without failing the audit row."""
    if record.status != SessionStatus.ISSUE_CREATED:
        record.status = SessionStatus.ISSUE_CREATED
        record.completed_at = utc_now()
    record.updated_at = utc_now()
    db.add(record)
    db.commit()
    db.refresh(record)
    notify()

    dispatched, skipped, failed = dispatch_audit_findings(findings)
    _apply_audit_dispatch_summary(record, len(findings), dispatched, skipped, failed)
    db.add(record)
    db.commit()
    notify()


def mark_record_failed(db: Session, record: RemediationSession, reason: str) -> None:
    record.status = SessionStatus.FAILED
    record.error_message = reason
    record.last_message = reason
    record.updated_at = utc_now()
    record.completed_at = utc_now()
    db.add(record)
    db.commit()
    notify()
