import json
from unittest.mock import MagicMock

from orchestrator import devin_client
from orchestrator.devin_client import DevinApiError


def test_devin_api_error_from_response_parses_detail():
    response = MagicMock()
    response.status_code = 403
    response.text = '{"detail":"Your organization has a billing error. Error: out_of_quota"}'
    response.json.return_value = {"detail": "Your organization has a billing error. Error: out_of_quota"}

    err = DevinApiError.from_response(response, "create session")

    assert err.status_code == 403
    assert "out_of_quota" in err.message
    assert "403" in err.user_message()
    assert "create session" in err.user_message()


def test_parse_done_pr_url():
    assert devin_client.parse_done_pr_url(["some update", "DONE: https://github.com/acme/repo/pull/42"]) == (
        "https://github.com/acme/repo/pull/42"
    )


def test_parse_blocked_reason():
    assert devin_client.parse_blocked_reason(["BLOCKED: missing GitHub access"]) == "missing GitHub access"


def test_parse_audit_done_payload():
    payload = [
        {
            "cve_id": "CVE-2026-45409",
            "package": "idna",
            "current_version": "3.10",
            "fix_versions": ["3.15"],
            "description": "demo",
            "github_issue_url": "https://github.com/example/superset/issues/1",
            "github_issue_number": 1,
        }
    ]

    findings = devin_client.parse_audit_done([f"AUDIT_DONE: {json.dumps(payload)}"])

    assert findings is not None
    assert findings[0].cve_id == "CVE-2026-45409"
    assert findings[0].fix_version == "3.15"


def test_sentinel_messages_ignore_user_prompt_blocked_template():
    session_data = {
        "messages": [
            "If you are blocked, reply with:\n  BLOCKED: <reason>\n",
            "AUDIT_DONE: []",
        ],
        "devin_messages": ["AUDIT_DONE: []"],
    }
    assert devin_client.parse_blocked_reason(devin_client.extract_sentinel_messages(session_data)) is None
    assert devin_client.parse_audit_done(devin_client.extract_sentinel_messages(session_data)) == []


def test_extract_messages_from_v3_message_items():
    session_data = {
        "messages": [
            {"event_id": "evt-1", "source": "user", "message": "run audit", "created_at": 1},
            {
                "event_id": "evt-2",
                "source": "devin",
                "message": "DONE: https://github.com/acme/repo/pull/9",
                "created_at": 2,
            },
        ]
    }
    assert devin_client.extract_messages(session_data) == [
        "run audit",
        "DONE: https://github.com/acme/repo/pull/9",
    ]
