# Show HN: HumanRoot – Cryptographic proof that every AI agent action traces back to a human

**Title:** Show HN: HumanRoot – Cryptographic proof that every AI agent action traces back to a human

---

AI agents are in production today. They send emails, execute API calls, write to databases, and delegate tasks to other agents.

But when you ask "who authorized this?" — there's no reliable answer. Delegation happens through system prompts, config checkboxes, OAuth scopes. None of these are signed, scoped, or propagatable across agent chains.

When Agent A delegates to Agent B delegates to Agent C, the original human intent disappears entirely.

**HumanRoot introduces one primitive: the Delegation Root Certificate (DRC).**

A DRC is a signed, structured record of a human delegation act. It carries:

- The human who authorized it (signed with ES256)
- The agent receiving authority
- Explicit scopes (email.read, database.write, etc.)
- Hard expiry
- Max delegation depth
- A revocation endpoint

When an agent sub-delegates, it issues a child DRC that can only restrict — never expand — the parent's authority. The root hash in every DRC always points back to the human-signed origin. The chain is always reconstructible.

**What it looks like in practice:**

```python
from humanroot import delegate

drc = delegate(
    human_id="alice@example.com",
    agent_id="my-agent-v1",
    scopes=["email.read", "calendar.write"],
    expires_in="24h",
)
```

One line. The DRC propagates automatically through all agent calls.

**Integrations ship on day one:** Anthropic Claude, OpenAI (chat + Assistants), LangChain (Runnable + callback), CrewAI. Each integration validates the DRC before every call and logs a structured action record referencing the DRC chain.

**There's also a CLI:**

```bash
humanroot keygen --out ./keys
humanroot issue --human-id alice@example.com --agent-id my-agent --scopes email.read --key ./keys/private.pem
humanroot chain --drc-id <uuid>
humanroot revoke --drc-id <uuid> --reason "key compromised"
```

**And a local dashboard** (chain explorer, revocation UI, audit export) served by the FastAPI server.

---

**Why not OAuth / IAM / JWTs?**

OAuth delegates to applications, not multi-hop agent chains. AWS IAM is single-provider. JWTs have no concept of delegation depth, child restriction, or cross-provider propagation. We're not replacing any of these — we're adding the layer they all miss: the human authorization origin.

**Why not a single provider?**

The value of a DRC is that it survives provider boundaries. If Anthropic or OpenAI issued and controlled the root certificate, competing providers wouldn't trust it, and the cross-provider chain breaks. An independent standard is structurally necessary.

**Where this goes:**

The pattern has repeated: PGP (1991) → eIDAS (2014). SSL (1994) → HTTPS mandated (2018). Technical adoption first, regulatory recognition second. The EU AI Act is asking the right questions about agentic systems. We want DRCs to be the answer before the regulation mandates something worse.

---

**Links:**

- PyPI: https://pypi.org/project/humanroot/
- GitHub: https://github.com/Thinklanceai/humanroot
- Spec: https://github.com/Thinklanceai/humanroot/blob/main/spec/DRC-SPEC-0.1.md

`pip install humanroot`

Open questions in the spec — identity methods, offline revocation, legal equivalence by jurisdiction. Feedback very welcome.
