"""
humanroot.integrations.anthropic_claude
----------------------------------------
Drop-in wrapper for the Anthropic Python SDK.

Usage:
    from anthropic import Anthropic
    from humanroot import delegate
    from humanroot.integrations.anthropic_claude import HumanRootAnthropic

    drc = delegate(
        human_id="alice@example.com",
        agent_id="claude-agent-v1",
        scopes=["text.generate"],
        expires_in="1h",
    )

    client = HumanRootAnthropic(drc=drc)

    # Identical to anthropic.Anthropic().messages.create(...)
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=1024,
        messages=[{"role": "user", "content": "Summarise this contract."}],
    )

The DRC is injected into the system prompt automatically.
Every call is validated and logged via build_action_record().
"""
from __future__ import annotations

from typing import Any

from humanroot.models import DelegationRootCertificate
from integrations.base import validate_before_call, build_action_record, DRCValidationError


class _MessagesWrapper:
    def __init__(self, client: Any, drc: DelegationRootCertificate):
        self._client = client
        self._drc = drc

    def create(self, **kwargs) -> Any:
        validate_before_call(self._drc)

        # Inject DRC context into system prompt
        drc_notice = (
            f"[HumanRoot] This session is authorised under DRC {self._drc.drc_id}. "
            f"Delegated by: {self._drc.principal.human_id}. "
            f"Permitted scopes: {', '.join(self._drc.authority.scopes)}."
        )
        existing_system = kwargs.get("system", "")
        kwargs["system"] = f"{drc_notice}\n\n{existing_system}".strip()

        record = build_action_record(
            self._drc, "anthropic", "messages.create",
            {"model": kwargs.get("model"), "messages_count": len(kwargs.get("messages", []))}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → {record['action']}")

        return self._client.messages.create(**kwargs)


class HumanRootAnthropic:
    """
    Wraps anthropic.Anthropic with DRC enforcement.
    Requires: pip install anthropic
    """
    def __init__(self, drc: DelegationRootCertificate, **anthropic_kwargs):
        try:
            import anthropic
            self._raw = anthropic.Anthropic(**anthropic_kwargs)
        except ImportError:
            raise ImportError("pip install anthropic")

        validate_before_call(drc)
        self._drc = drc
        self.messages = _MessagesWrapper(self._raw, drc)
