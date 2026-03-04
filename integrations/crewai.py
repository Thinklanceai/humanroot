"""
humanroot.integrations.crewai
-------------------------------
DRC enforcement for CrewAI agents and tasks.

Usage:
    from crewai import Agent, Task, Crew
    from humanroot import delegate
    from humanroot.integrations.crewai import drc_crew, DRCAgentWrapper

    drc = delegate(
        human_id="alice@example.com",
        agent_id="crewai-agent-v1",
        scopes=["text.generate", "tool.use"],
        expires_in="2h",
        max_delegation_depth=3,
    )

    researcher = Agent(role="Researcher", goal="...", backstory="...")
    task = Task(description="...", agent=researcher)

    # Wrap the entire crew
    crew = drc_crew(Crew(agents=[researcher], tasks=[task]), drc)
    result = crew.kickoff()
"""
from __future__ import annotations

from typing import Any

from humanroot.models import DelegationRootCertificate
from integrations.base import validate_before_call, build_action_record


class DRCCrewWrapper:
    """
    Wraps a CrewAI Crew instance with DRC enforcement.
    Validates the DRC before kickoff and logs the action.
    """
    def __init__(self, crew: Any, drc: DelegationRootCertificate):
        self._crew = crew
        self._drc = drc

    def kickoff(self, inputs: dict | None = None) -> Any:
        validate_before_call(self._drc)

        agent_roles = []
        try:
            agent_roles = [a.role for a in self._crew.agents]
        except Exception:
            pass

        record = build_action_record(
            self._drc, "crewai", "crew.kickoff",
            {"agents": agent_roles, "inputs": inputs or {}}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → crew.kickoff agents={agent_roles}")

        if inputs is not None:
            return self._crew.kickoff(inputs=inputs)
        return self._crew.kickoff()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._crew, name)


class DRCAgentWrapper:
    """
    Wraps a single CrewAI Agent with DRC enforcement.
    Intercepts execute_task calls.
    """
    def __init__(self, agent: Any, drc: DelegationRootCertificate):
        self._agent = agent
        self._drc = drc

    def execute_task(self, task: Any, *args, **kwargs) -> Any:
        validate_before_call(self._drc)
        task_desc = getattr(task, "description", str(task))
        record = build_action_record(
            self._drc, "crewai", "agent.execute_task",
            {"task": task_desc}
        )
        print(f"[HumanRoot] action_record: {record['drc_id']} → agent.execute_task")
        return self._agent.execute_task(task, *args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._agent, name)


def drc_crew(crew: Any, drc: DelegationRootCertificate) -> DRCCrewWrapper:
    """Wrap a CrewAI Crew with DRC enforcement."""
    validate_before_call(drc)
    return DRCCrewWrapper(crew, drc)


def drc_agent(agent: Any, drc: DelegationRootCertificate) -> DRCAgentWrapper:
    """Wrap a single CrewAI Agent with DRC enforcement."""
    validate_before_call(drc)
    return DRCAgentWrapper(agent, drc)
