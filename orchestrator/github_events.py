"""Apply GitHub PR state to remediation sessions (polled)."""

from __future__ import annotations

import logging
import re
from typing import Any

from sqlmodel import Session, select

from orchestrator import github_client
from orchestrator.config import settings
from orchestrator.events import notify
from orchestrator.models import RemediationSession, SessionStatus, SessionType, utc_now

logger = logging.getLogger(__name__)

CLOSES_ISSUE_PATTERN = re.compile(r"(?i)closes\s+#(\d+)")
ISSUE_REF_PATTERN = re.compile(r"#(\d+)")


def issue_numbers_in_pr_body(body: str) -> list[int]:
    """Issue numbers referenced in a PR body (Closes #N preferred, then any #N)."""
    if not body:
        return []
    closes = [int(match.group(1)) for match in CLOSES_ISSUE_PATTERN.finditer(body)]
    if closes:
        return list(dict.fromkeys(closes))
    refs = [int(match.group(1)) for match in ISSUE_REF_PATTERN.finditer(body)]
    return list(dict.fromkeys(refs))


def _record_for_issue(db: Session, issue_number: int) -> RemediationSession | None:
    return db.exec(
        select(RemediationSession).where(
            RemediationSession.session_type == SessionType.REMEDIATION,
            RemediationSession.github_issue_number == issue_number,
        )
    ).first()


def _status_from_pr(pr: dict[str, Any]) -> SessionStatus:
    if pr.get("merged_at"):
        return SessionStatus.MERGED
    return SessionStatus.PR_OPENED


def apply_pr_to_record(record: RemediationSession, pr: dict[str, Any]) -> bool:
    """Update a remediation row from GitHub pull request metadata. Returns True if changed."""
    new_status = _status_from_pr(pr)
    pr_url = pr.get("html_url")
    pr_number = pr.get("number")

    changed = False
    if pr_url and record.github_pr_url != pr_url:
        record.github_pr_url = pr_url
        changed = True
    if pr_number and record.github_pr_number != pr_number:
        record.github_pr_number = int(pr_number)
        changed = True
    if record.status != new_status:
        record.status = new_status
        changed = True

    if changed:
        record.updated_at = utc_now()
        if new_status in {SessionStatus.PR_OPENED, SessionStatus.MERGED}:
            record.completed_at = utc_now()
            if not record.last_message or record.last_message.startswith("Devin remediation"):
                record.last_message = f"PR detected on GitHub: {pr_url or pr_number}"

    return changed


def sync_github_for_record(db: Session, record: RemediationSession) -> bool:
    """Poll GitHub for PR / merge state linked to this remediation session."""
    if record.session_type != SessionType.REMEDIATION or not record.github_issue_number:
        return False
    if record.status not in {SessionStatus.IN_PROGRESS, SessionStatus.PR_OPENED}:
        return False
    if not settings.github_poll_enabled:
        return False

    if record.status == SessionStatus.PR_OPENED and record.github_pr_number:
        pr = github_client.get_pull(record.github_pr_number)
    else:
        pr = github_client.find_pr_for_issue(record.github_issue_number)

    if not pr:
        return False

    if apply_pr_to_record(record, pr):
        db.add(record)
        db.commit()
        notify()
        logger.info(
            "GitHub poll: session %s -> %s (PR #%s)",
            record.id,
            record.status.value,
            record.github_pr_number,
        )
        return True
    return False
