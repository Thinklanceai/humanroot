# Outreach Templates

## Legal Tech Firms

**Subject:** AI agent authorization — a gap your clients are about to ask about

Hi [Name],

I'm reaching out because you sit at the intersection of AI adoption and legal defensibility — exactly where a problem I've been working on becomes relevant.

When an AI agent takes an action today — sends an email, executes a transaction, delegates to another agent — there is no structured, signed record of who authorized it. The delegation happened through a system prompt or a config checkbox. That's not defensible in a dispute, an audit, or a regulatory inquiry.

I built HumanRoot to solve this. It introduces a single primitive: the Delegation Root Certificate (DRC). A DRC is a cryptographically signed, scope-bound, propagatable record of a human delegation act. It survives multi-hop agent chains and provider boundaries. It's the difference between "we had a system prompt" and "here is a signed authorization chain from the human to the action."

It's open source, on PyPI today: https://pypi.org/project/humanroot/

I'd value 20 minutes to understand how your clients are currently handling agentic authorization, and whether DRCs could be useful as a legal standard for their compliance frameworks.

[Your name]

---

## Cyber Insurers

**Subject:** AI agent liability — the authorization gap

Hi [Name],

Cyber insurance is starting to price AI agent risk. The hard question is: when an agent causes harm, can the policyholder prove a human authorized the action?

Today the answer is almost always no. Delegation to AI agents happens through informal mechanisms — system prompts, OAuth scopes, API keys. None of these are signed, scoped, or traceable across multi-hop agent chains.

HumanRoot introduces the Delegation Root Certificate: a cryptographic standard for human→agent authorization. Every action references a DRC. Every DRC traces back to a human signature. The chain is always reconstructible and auditable.

This is the kind of control that belongs in an AI agent risk framework — the way MFA became a requirement for cyber coverage, DRCs could become a requirement for agentic system coverage.

Open source, on PyPI: https://pypi.org/project/humanroot/
Spec: https://github.com/Thinklanceai/humanroot/blob/main/spec/DRC-SPEC-0.1.md

Happy to walk through the technical details or discuss how this maps to your underwriting criteria.

[Your name]

---

## Target List

### Legal Tech (10)
1. Ironclad — contract AI, agentic workflows
2. Harvey — AI legal research and drafting
3. Clio — legal practice management + AI
4. Luminance — AI for legal due diligence
5. Relativity — e-discovery, AI review
6. Kira Systems — contract analysis
7. Legl — legal operations
8. Litera — legal document management
9. NetDocuments — document management + AI
10. Filevine — legal project management

### Cyber Insurers (5)
1. Coalition — cyber insurance, heavy tech focus
2. At-Bay — cyber insurance + risk monitoring
3. Cowbell — SMB cyber insurance
4. Resilience — cyber risk + insurance
5. Corvus Insurance — AI-driven cyber underwriting
