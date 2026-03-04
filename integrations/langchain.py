"""
humanroot.integrations.langchain
----------------------------------
DRC-aware wrappers for LangChain chains and agents.

Usage:
    from langchain_openai import ChatOpenAI
    from langchain_core.messages import HumanMessage
    from humanroot import delegate
    from humanroot.integrations.langchain import drc_runnable, DRCCallbackHandler

    drc = delegate(
        human_id="alice@example.com",
        agent_id="langchain-agent-v1",
        scopes=["text.generate", "tool.use"],
        expires_in="1h",
    )

    llm = ChatOpenAI(model="gpt-4o")

    # Option A: wrap any Runnable
    secured_llm = drc_runnable(llm, drc)
    result = secured_llm.invoke([HumanMessage(content="Hello")])

    # Option B: attach as a callback handler (non-invasive)
    result = llm.invoke(
        [HumanMessage(content="Hello")],
        config={"callbacks": [DRCCallbackHandler(drc)]}
    )
"""
from __future__ import annotations

from typing import Any

from humanroot.models import DelegationRootCertificate
from integrations.base import validate_before_call, build_action_record, DRCValidationError


# ---------------------------------------------------------------------------
# Option A: Runnable wrapper
# ---------------------------------------------------------------------------

class DRCRunnable:
    """
    Wraps any LangChain Runnable.
    Validates DRC on every .invoke() / .stream() call.
    """
    def __init__(self, runnable: Any, drc: DelegationRootCertificate):
        self._runnable = runnable
        self._drc = drc

    def invoke(self, input: Any, config: dict | None = None, **kwargs) -> Any:
        validate_before_call(self._drc)
        record = build_action_record(
            self._drc, "langchain", "runnable.invoke",
            {"input_type": type(input).__name__}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → {record['action']}")
        return self._runnable.invoke(input, config=config, **kwargs)

    def stream(self, input: Any, config: dict | None = None, **kwargs):
        validate_before_call(self._drc)
        record = build_action_record(
            self._drc, "langchain", "runnable.stream",
            {"input_type": type(input).__name__}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → {record['action']}")
        yield from self._runnable.stream(input, config=config, **kwargs)

    def batch(self, inputs: list, config: dict | None = None, **kwargs) -> list:
        validate_before_call(self._drc)
        return [self.invoke(i, config=config, **kwargs) for i in inputs]

    # Pass through anything else (pipe operator, etc.)
    def __or__(self, other):
        from integrations.langchain import DRCRunnable
        try:
            chained = self._runnable | other
            return DRCRunnable(chained, self._drc)
        except Exception:
            raise


def drc_runnable(runnable: Any, drc: DelegationRootCertificate) -> DRCRunnable:
    """Wrap any LangChain Runnable with DRC enforcement."""
    validate_before_call(drc)
    return DRCRunnable(runnable, drc)


# ---------------------------------------------------------------------------
# Option B: Callback handler (non-invasive)
# ---------------------------------------------------------------------------

class DRCCallbackHandler:
    """
    LangChain callback handler that validates the DRC before each LLM call.
    Attach via config={"callbacks": [DRCCallbackHandler(drc)]}.
    Compatible with langchain_core.callbacks.BaseCallbackHandler.
    """
    def __init__(self, drc: DelegationRootCertificate):
        self._drc = drc

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs) -> None:
        validate_before_call(self._drc)
        record = build_action_record(
            self._drc, "langchain_callback", "llm_start",
            {"model": serialized.get("name", "unknown"), "prompts_count": len(prompts)}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → llm_start")

    def on_chat_model_start(self, serialized: dict, messages: list, **kwargs) -> None:
        validate_before_call(self._drc)
        record = build_action_record(
            self._drc, "langchain_callback", "chat_model_start",
            {"model": serialized.get("name", "unknown")}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → chat_model_start")

    def on_tool_start(self, serialized: dict, input_str: str, **kwargs) -> None:
        validate_before_call(self._drc)
        record = build_action_record(
            self._drc, "langchain_callback", "tool_start",
            {"tool": serialized.get("name", "unknown"), "input": input_str}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → tool_start:{record['inputs_summary'].get('tool')}")

    # No-op handlers required by LangChain callback interface
    def on_llm_end(self, *args, **kwargs): pass
    def on_llm_error(self, *args, **kwargs): pass
    def on_chain_start(self, *args, **kwargs): pass
    def on_chain_end(self, *args, **kwargs): pass
    def on_chain_error(self, *args, **kwargs): pass
    def on_tool_end(self, *args, **kwargs): pass
    def on_tool_error(self, *args, **kwargs): pass
    def on_agent_action(self, *args, **kwargs): pass
    def on_agent_finish(self, *args, **kwargs): pass
