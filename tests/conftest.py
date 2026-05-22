import os
from unittest.mock import patch

import pytest
from sqlmodel import SQLModel

os.environ.setdefault("DEVIN_API_KEY", "test-devin-key")
os.environ.setdefault("DEVIN_ORG_ID", "org-test")
os.environ.setdefault("DEVIN_BASE_URL", "https://api.devin.ai/v3")
os.environ.setdefault("GITHUB_TOKEN", "test-github-token")
os.environ.setdefault("GITHUB_REPO", "example/superset")
os.environ.setdefault("DATABASE_URL", "sqlite:///./test_sentinel.db")

from tests import fakes  # noqa: E402


@pytest.fixture(autouse=True)
def patched_clients():
    from orchestrator.database import engine

    fakes.reset_fakes()
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)

    with (
        patch("orchestrator.devin_client.create_session", side_effect=fakes.fake_create_session),
        patch("orchestrator.devin_client.get_session", side_effect=fakes.fake_get_session),
        patch("orchestrator.devin_client.list_organization_sessions", return_value=[]),
        patch("orchestrator.devin_client.list_active_devin_sessions", return_value=[]),
        patch("orchestrator.github_client.create_issue", side_effect=lambda **kwargs: fakes.make_issue(
            cve_id=kwargs.get("cve_id", "CVE-TEST"),
            package=kwargs.get("package", "pkg"),
        )),
        patch("orchestrator.github_client.get_open_issues_with_label", return_value=[]),
        patch("orchestrator.github_client.find_issue_by_cve", return_value=None),
        patch("orchestrator.github_client.get_pull", return_value=None),
        patch("orchestrator.github_client.find_pr_for_issue", return_value=None),
        patch("orchestrator.github_client.get_branch_head_sha", side_effect=fakes.get_branch_head),
        patch("orchestrator.github_client.ensure_labels"),
    ):
        yield

    SQLModel.metadata.drop_all(engine)
