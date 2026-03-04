"""
humanroot.integrations.openai_chat
------------------------------------
Drop-in wrapper for the OpenAI Python SDK (chat completions + Assistants).

Usage:
    from openai import OpenAI
    from humanroot import delegate
    from humanroot.integrations.openai_chat import HumanRootOpenAI

    drc = delegate(
        human_id="alice@example.com",
        agent_id="gpt-agent-v1",
        scopes=["text.generate"],
        expires_in="1h",
    )

    client = HumanRootOpenAI(drc=drc)

    # Chat completions — identical API to openai.OpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Draft this email."}],
    )

    # Assistants runs
    run = client.beta.threads.runs.create(
        thread_id="thread_xxx",
        assistant_id="asst_xxx",
    )
"""
from __future__ import annotations

from typing import Any

from humanroot.models import DelegationRootCertificate
from integrations.base import validate_before_call, build_action_record


class _ChatCompletionsWrapper:
    def __init__(self, client: Any, drc: DelegationRootCertificate):
        self._client = client
        self._drc = drc

    def create(self, **kwargs) -> Any:
        validate_before_call(self._drc)

        # Prepend DRC system message
        messages = list(kwargs.get("messages", []))
        drc_system = {
            "role": "system",
            "content": (
                f"[HumanRoot] Authorised under DRC {self._drc.drc_id}. "
                f"Delegated by: {self._drc.principal.human_id}. "
                f"Scopes: {', '.join(self._drc.authority.scopes)}."
            ),
        }
        # Insert at front only if no system message already
        if not messages or messages[0].get("role") != "system":
            messages.insert(0, drc_system)
        else:
            messages[0]["content"] = drc_system["content"] + "\n\n" + messages[0]["content"]

        kwargs["messages"] = messages

        record = build_action_record(
            self._drc, "openai", "chat.completions.create",
            {"model": kwargs.get("model"), "messages_count": len(messages)}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → {record['action']}")

        return self._client.chat.completions.create(**kwargs)


class _RunsWrapper:
    def __init__(self, client: Any, drc: DelegationRootCertificate):
        self._client = client
        self._drc = drc

    def create(self, thread_id: str, assistant_id: str, **kwargs) -> Any:
        validate_before_call(self._drc)

        # Attach DRC metadata as additional instructions
        drc_instructions = (
            f"[HumanRoot] DRC {self._drc.drc_id} | "
            f"Delegated by {self._drc.principal.human_id} | "
            f"Scopes: {', '.join(self._drc.authority.scopes)}"
        )
        existing = kwargs.get("additional_instructions", "")
        kwargs["additional_instructions"] = f"{drc_instructions}\n{existing}".strip()

        record = build_action_record(
            self._drc, "openai_assistants", "threads.runs.create",
            {"thread_id": thread_id, "assistant_id": assistant_id}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → {record['action']}")

        return self._client.beta.threads.runs.create(
            thread_id=thread_id, assistant_id=assistant_id, **kwargs
        )


class _BetaThreadsRuns:
    def __init__(self, client: Any, drc: DelegationRootCertificate):
        self.runs = _RunsWrapper(client, drc)


class _Beta:
    def __init__(self, client: Any, drc: DelegationRootCertificate):
        self.threads = _BetaThreadsRuns(client, drc)


class HumanRootOpenAI:
    """
    Wraps openai.OpenAI with DRC enforcement.
    Requires: pip install openai
    """
    def __init__(self, drc: DelegationRootCertificate, **openai_kwargs):
        try:
            import openai
            self._raw = openai.OpenAI(**openai_kwargs)
        except ImportError:
            raise ImportError("pip install openai")

        validate_before_call(drc)
        self._drc = drc
        self.chat = type("chat", (), {
            "completions": _ChatCompletionsWrapper(self._raw, drc)
        })()
        self.beta = _Beta(self._raw, drc)
