from unittest.mock import patch

from orchestrator import devin_client
from orchestrator import orchestrator as orch
from orchestrator.devin_client import DevinApiError
from orchestrator.models import SessionStatus, SessionType


def test_start_devin_audit_records_failed_on_quota_error():
    quota_error = DevinApiError(
        403,
        "Your organization has a billing error. Error: out_of_quota",
        context="create session",
    )
    with patch("orchestrator.orchestrator.devin_client.create_session", side_effect=quota_error):
        record = orch.start_devin_audit()

    assert record.session_type == SessionType.AUDIT
    assert record.status == SessionStatus.FAILED
    assert record.error_message is not None
    assert "out_of_quota" in record.error_message
    assert record.devin_session_id is None


def test_session_list_cutoff_uses_lookback_hours():
    with patch.object(devin_client.settings, "devin_session_lookback_hours", 12):
        with patch("orchestrator.devin_client.time.time", return_value=1_000_000):
            assert devin_client._session_list_cutoff_epoch() == 1_000_000 - 12 * 3600
