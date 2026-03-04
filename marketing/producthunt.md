# ProductHunt Launch

## Tagline
Cryptographic proof that every AI agent action traces back to a human decision.

## Description
AI agents are running in production — sending emails, executing API calls, writing to databases, delegating to other agents. But when something goes wrong, there's no reliable answer to "who authorized this?"

**HumanRoot** introduces the Delegation Root Certificate (DRC): a signed, structured record of every human→agent delegation. One line of code. Works with Anthropic, OpenAI, LangChain, and CrewAI out of the box.

**What it does:**
→ Cryptographically links every agent action back to the human who authorized it
→ Enforces scope restriction across multi-hop agent chains
→ Instant revocation that cascades to all child delegations
→ Provider-agnostic — survives OpenAI → Anthropic → custom agent chains
→ CLI, dashboard, audit export included

**Who it's for:**
→ Developers building agentic systems who need defensible authorization records
→ Legal tech and fintech teams facing agentic audit requirements
→ Cyber insurers building AI agent liability products

`pip install humanroot`

## First Comment
Hey PH 👋

I built HumanRoot because I kept asking the same question while building agentic systems: if an agent does something wrong, can I prove a human authorized it?

The answer today is: not really. System prompts aren't signed. Config checkboxes aren't scoped. OAuth wasn't designed for multi-hop agent chains.

The DRC is a single new primitive that fills this gap. It's not trying to replace OAuth or IAM — it's the layer they all miss: the human authorization origin, cryptographically signed, propagatable across any provider.

The spec is in the repo. Open questions are documented. I want this to be a standard, not a product — feedback on the spec is as valuable as stars.

GitHub: https://github.com/Thinklanceai/humanroot
PyPI: https://pypi.org/project/humanroot/
