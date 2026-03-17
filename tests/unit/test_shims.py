"""
tests/unit/test_shims.py — Tests for the four lightweight shim modules.

These tests verify the shims behave identically to the SAO SDK interface.
If a shim fails these tests, the migration swap may break agent behaviour.

Run: pytest tests/unit/test_shims.py -v
"""

import asyncio, json, sys
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import pytest


# ── Quality Signal shim ───────────────────────────────────────────────────────

class TestQualitySignalShim:
    """Verify QualitySignal produces correct schema for SAO routing."""

    def _make_qs(self, passed=True):
        from core.quality_signal import QualitySignal, Check, Severity
        checks = [
            Check(check_id="test_check", name="Test check", severity=Severity.HIGH,
                  passed=passed, expected=1, actual=1 if passed else 0,
                  delta=0.0 if passed else -1.0, message="test"),
        ]
        return QualitySignal(
            job_id   = "test-job-001",
            agent_id = "SOC-TRIAGE-001",
            passed   = passed,
            checks   = checks,
        )

    def test_quality_signal_passed_field(self):
        qs = self._make_qs(passed=True)
        assert qs.passed is True

    def test_quality_signal_failed_field(self):
        qs = self._make_qs(passed=False)
        assert qs.passed is False

    def test_failed_high_checks(self):
        from core.quality_signal import QualitySignal, Check, Severity
        checks = [
            Check(check_id="c1", name="Check 1", severity=Severity.HIGH, passed=False),
            Check(check_id="c2", name="Check 2", severity=Severity.HIGH, passed=True),
            Check(check_id="c3", name="Check 3", severity=Severity.MEDIUM, passed=False),
        ]
        qs = QualitySignal(job_id="j1", agent_id="SOC-TRIAGE-001", passed=False, checks=checks)
        failed_high = qs.failed_high_checks
        assert len(failed_high) == 1
        assert failed_high[0].check_id == "c1"

    def test_check_to_dict_schema(self):
        from core.quality_signal import Check, Severity
        c = Check(check_id="test", name="Test", severity=Severity.HIGH,
                  passed=True, expected=1.0, actual=1.0, delta=0.0, message="ok")
        d = c.to_dict()
        assert "check_id"   in d
        assert "name"       in d
        assert "severity"   in d
        assert "passed"     in d
        assert "expected"   in d
        assert "actual"     in d
        assert "delta"      in d
        assert "message"    in d
        assert "field_path" in d

    @pytest.mark.asyncio
    async def test_emit_calls_postgres(self):
        """Verify emit() attempts to write to PostgreSQL."""
        from core.quality_signal import QualitySignal, Severity
        qs = self._make_qs(passed=True)

        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        with patch("asyncpg.connect", new_callable=AsyncMock, return_value=mock_conn), \
             patch("httpx.AsyncClient") as mock_http:
            mock_http.return_value.__aenter__ = AsyncMock(return_value=MagicMock(
                post=AsyncMock()
            ))
            mock_http.return_value.__aexit__ = AsyncMock(return_value=None)
            await qs.emit()
            mock_conn.execute.assert_called_once()
            # Verify it was an INSERT
            call_args = mock_conn.execute.call_args[0][0]
            assert "INSERT" in call_args.upper() or "quality_signals" in call_args


# ── Cost tracker shim ─────────────────────────────────────────────────────────

class TestCostTrackerShim:
    def test_required_fields_documented(self):
        """Verify write_token_cost_event accepts the required fields."""
        import inspect
        from core.cost_tracker import write_token_cost_event
        sig = inspect.signature(write_token_cost_event)
        assert "event" in sig.parameters, "write_token_cost_event must accept 'event' dict"

    def test_event_schema_matches_sao_sdk(self):
        """The event dict schema must be identical to SAO SDK."""
        required_fields = {
            "job_id", "tenant_id", "department_id", "agent_id",
            "model", "node_name", "prompt_tokens", "completion_tokens", "cost_usd"
        }
        # These are the fields the agent passes — verify they're all documented in the shim
        import inspect
        from core import cost_tracker
        source = inspect.getsource(cost_tracker)
        for field in required_fields:
            assert field in source, f"Required field '{field}' not referenced in cost_tracker.py"


# ── HITL client shim ──────────────────────────────────────────────────────────

class TestHITLClientShim:
    @pytest.mark.asyncio
    async def test_submit_hitl_job_posts_to_ui(self):
        """submit_hitl_job must POST to the HITL UI endpoint."""
        from core.hitl_client import submit_hitl_job
        mock_response = MagicMock(status_code=200)
        mock_response.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__  = AsyncMock(return_value=None)

            await submit_hitl_job(
                job_id="test-001", agent_id="SOC-AUDITOR-001",
                tenant_id="tenant-pilot-id", jurisdiction="ID",
                draft={"field": "value"}, qs_payload={},
            )
            mock_instance.post.assert_called_once()
            call_url = mock_instance.post.call_args[0][0]
            assert "/hitl/jobs" in call_url

    @pytest.mark.asyncio
    async def test_get_hitl_decision_returns_none_when_pending(self):
        """Returns None when no decision made yet (404 response)."""
        from core.hitl_client import get_hitl_decision
        mock_response = MagicMock()
        mock_response.status_code = 404

        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.get = AsyncMock(return_value=mock_response)
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__  = AsyncMock(return_value=None)

            result = await get_hitl_decision("pending-job-001")
            assert result is None


# ── Logger shim ───────────────────────────────────────────────────────────────

class TestLoggerShim:
    def test_get_logger_returns_logger(self):
        import logging
        from core.logger import get_logger
        logger = get_logger("test.module")
        assert isinstance(logger, logging.Logger)

    def test_logger_is_structured(self):
        """Logger must have a structured formatter attached."""
        from core.logger import get_logger, _StructuredFormatter
        logger = get_logger("test.structured")
        has_structured = any(
            isinstance(h.formatter, _StructuredFormatter)
            for h in logger.handlers
        )
        assert has_structured, "Logger must use _StructuredFormatter for JSON output"

    def test_logger_output_is_valid_json(self, capsys):
        """Logger output must be parseable JSON."""
        import logging
        from core.logger import get_logger
        logger = get_logger("test.json.output")
        logger.info("test_event", extra={"key": "value", "count": 42})
        captured = capsys.readouterr()
        if captured.out.strip():
            data = json.loads(captured.out.strip())
            assert "timestamp" in data
            assert "level"     in data
            assert "message"   in data

    def test_same_name_returns_same_logger(self):
        """get_logger with same name should return same instance (no duplicate handlers)."""
        from core.logger import get_logger
        l1 = get_logger("test.idempotent")
        l2 = get_logger("test.idempotent")
        assert l1 is l2


# ── OPA client tests ──────────────────────────────────────────────────────────

class TestOPAClient:
    @pytest.mark.asyncio
    async def test_fails_closed_on_timeout(self):
        """OPA unreachable must return (False, 'opa_timeout') — never True."""
        from core.opa_client import check_action
        import httpx
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__  = AsyncMock(return_value=None)
            allow, risk = await check_action({"identity_type":"service","agent_id":"SOC-TRIAGE-001"})
            assert allow is False
            assert "timeout" in risk

    @pytest.mark.asyncio
    async def test_fails_closed_on_connection_error(self):
        from core.opa_client import check_action
        with patch("httpx.AsyncClient") as mock_client:
            mock_instance = AsyncMock()
            mock_instance.post = AsyncMock(side_effect=Exception("connection refused"))
            mock_client.return_value.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_client.return_value.__aexit__  = AsyncMock(return_value=None)
            allow, _ = await check_action({})
            assert allow is False


# ── Tier classifier + shim integration ───────────────────────────────────────

class TestTierClassifierInvariant:
    """The tier classifier must never import from any shim or SAO SDK."""

    def test_no_shim_imports(self):
        import ast
        src = Path("agents/triage/tier_classifier.py").read_text()
        tree= ast.parse(src)
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                imports.append(ast.dump(node))
        shim_imports = [i for i in imports
                        if "quality_signal" in i or "cost_tracker" in i
                        or "hitl_client" in i or "sao_sdk" in i]
        assert not shim_imports, f"tier_classifier.py must not import shims: {shim_imports}"

    def test_no_async_in_classify_tier(self):
        """classify_tier must be synchronous — deterministic, no I/O."""
        from agents.triage.tier_classifier import classify_tier
        import asyncio
        assert not asyncio.iscoroutinefunction(classify_tier)
