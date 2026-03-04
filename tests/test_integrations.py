"""
Tests for framework integrations.
Uses mock clients — no real API keys required.
"""
import unittest
from datetime import timedelta, timezone, datetime
from unittest.mock import MagicMock

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from humanroot import delegate
from integrations.base import validate_before_call, build_action_record, DRCValidationError
from integrations.langchain import drc_runnable, DRCCallbackHandler
from integrations.crewai import drc_crew, drc_agent


def make_drc(**kwargs):
    defaults = dict(
        human_id="alice@example.com",
        agent_id="test-agent",
        scopes=["text.generate", "tool.use"],
        expires_in="1h",
    )
    defaults.update(kwargs)
    return delegate(**defaults)


class TestBase(unittest.TestCase):
    def test_validate_ok(self):
        drc = make_drc()
        validate_before_call(drc)  # should not raise

    def test_validate_none_raises(self):
        with self.assertRaises(DRCValidationError):
            validate_before_call(None)

    def test_validate_expired_raises(self):
        now = datetime.now(timezone.utc)
        from humanroot.models import DelegationRootCertificate, Principal, AgentRef, Authority
        drc = DelegationRootCertificate(
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            principal=Principal(human_id="alice@example.com"),
            agent=AgentRef(agent_id="agent-1"),
            authority=Authority(scopes=["text.generate"]),
        )
        with self.assertRaises(DRCValidationError):
            validate_before_call(drc)

    def test_build_action_record(self):
        drc = make_drc()
        record = build_action_record(drc, "test", "some.action", {"key": "value"})
        self.assertEqual(record["drc_id"], drc.drc_id)
        self.assertEqual(record["framework"], "test")
        self.assertEqual(record["action"], "some.action")
        self.assertEqual(record["human_id"], "alice@example.com")
        self.assertIn("recorded_at", record)


class TestLangChainRunnable(unittest.TestCase):
    def test_invoke_calls_through(self):
        drc = make_drc()
        mock_runnable = MagicMock()
        mock_runnable.invoke.return_value = "result"

        wrapped = drc_runnable(mock_runnable, drc)
        result = wrapped.invoke("hello")

        self.assertEqual(result, "result")
        mock_runnable.invoke.assert_called_once_with("hello", config=None)

    def test_batch_calls_invoke_multiple(self):
        drc = make_drc()
        mock_runnable = MagicMock()
        mock_runnable.invoke.return_value = "ok"

        wrapped = drc_runnable(mock_runnable, drc)
        results = wrapped.batch(["a", "b", "c"])

        self.assertEqual(len(results), 3)
        self.assertEqual(mock_runnable.invoke.call_count, 3)

    def test_expired_drc_raises_on_invoke(self):
        now = datetime.now(timezone.utc)
        from humanroot.models import DelegationRootCertificate, Principal, AgentRef, Authority
        expired_drc = DelegationRootCertificate(
            issued_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
            principal=Principal(human_id="alice@example.com"),
            agent=AgentRef(agent_id="agent-1"),
            authority=Authority(scopes=["text.generate"]),
        )
        mock_runnable = MagicMock()
        wrapped = drc_runnable.__wrapped__ = None  # bypass validate on wrap

        from integrations.langchain import DRCRunnable
        wrapped = DRCRunnable(mock_runnable, expired_drc)
        with self.assertRaises(DRCValidationError):
            wrapped.invoke("hello")


class TestLangChainCallback(unittest.TestCase):
    def test_on_llm_start_validates(self):
        drc = make_drc()
        handler = DRCCallbackHandler(drc)
        # Should not raise
        handler.on_llm_start({"name": "gpt-4"}, ["prompt"])

    def test_on_tool_start_validates(self):
        drc = make_drc()
        handler = DRCCallbackHandler(drc)
        handler.on_tool_start({"name": "search"}, "query")


class TestCrewAI(unittest.TestCase):
    def test_crew_kickoff_calls_through(self):
        drc = make_drc()
        mock_crew = MagicMock()
        mock_crew.agents = []
        mock_crew.kickoff.return_value = "crew_result"

        wrapped = drc_crew(mock_crew, drc)
        result = wrapped.kickoff()

        self.assertEqual(result, "crew_result")
        mock_crew.kickoff.assert_called_once()

    def test_crew_kickoff_with_inputs(self):
        drc = make_drc()
        mock_crew = MagicMock()
        mock_crew.agents = []
        mock_crew.kickoff.return_value = "ok"

        wrapped = drc_crew(mock_crew, drc)
        wrapped.kickoff(inputs={"topic": "AI"})

        mock_crew.kickoff.assert_called_once_with(inputs={"topic": "AI"})

    def test_agent_execute_task_calls_through(self):
        drc = make_drc()
        mock_agent = MagicMock()
        mock_agent.execute_task.return_value = "task_result"
        mock_task = MagicMock()
        mock_task.description = "research AI"

        wrapped = drc_agent(mock_agent, drc)
        result = wrapped.execute_task(mock_task)

        self.assertEqual(result, "task_result")
        mock_agent.execute_task.assert_called_once_with(mock_task)


if __name__ == "__main__":
    unittest.main()
