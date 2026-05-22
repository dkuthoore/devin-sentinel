from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel
from pydantic import Field as PydanticField
from sqlmodel import Field, SQLModel


def utc_now() -> datetime:
    return datetime.now(UTC)


class SessionType(StrEnum):
    AUDIT = "audit"
    REMEDIATION = "remediation"


class SessionStatus(StrEnum):
    PENDING = "pending"
    AUDIT_RUNNING = "audit_running"
    ISSUE_CREATED = "issue_created"
    IN_PROGRESS = "in_progress"
    PR_OPENED = "pr_opened"
    MERGED = "merged"
    FAILED = "failed"


class CveFinding(BaseModel):
    cve_id: str
    package: str
    current_version: str
    fix_versions: list[str] = PydanticField(default_factory=list)
    description: str = ""
    github_issue_number: int | None = None
    github_issue_url: str | None = None

    @property
    def fix_version(self) -> str | None:
        return self.fix_versions[0] if self.fix_versions else None


class RepoWatchState(SQLModel, table=True):
    """Tracks last-seen default-branch HEAD to detect pushes via polling."""

    repo: str = Field(primary_key=True)
    branch: str = Field(primary_key=True)
    last_sha: str | None = None
    updated_at: datetime = Field(default_factory=utc_now)


class RemediationSession(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)

    session_type: SessionType = Field(index=True)
    status: SessionStatus = Field(default=SessionStatus.PENDING, index=True)

    cve_id: str | None = Field(default=None, index=True)
    package: str | None = None
    current_version: str | None = None
    fix_version: str | None = None
    description: str = ""

    github_issue_number: int | None = None
    github_issue_url: str | None = None
    github_pr_number: int | None = None
    github_pr_url: str | None = None

    devin_session_id: str | None = Field(default=None, index=True)
    devin_session_url: str | None = None

    last_message: str | None = None
    error_message: str | None = None

    created_at: datetime = Field(default_factory=utc_now)
    updated_at: datetime = Field(default_factory=utc_now)
    completed_at: datetime | None = None


class SessionSyncRequest(BaseModel):
    devin_session_id: str | None = None


class SessionSyncResponse(BaseModel):
    synced: int
    status: str = "ok"


class Metrics(BaseModel):
    total_cves_detected: int
    audit_sessions: int
    remediation_sessions: int
    issues_created: int
    devin_sessions: int
    prs_opened: int
    merged: int
    failed: int
    by_status: dict[str, int]
    avg_resolution_minutes: float | None
    packages_affected: list[str]
