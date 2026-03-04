# DRC-SPEC-0.1 — Delegation Root Certificate Specification

**Status:** Working Draft  
**Version:** 0.1  
**Date:** 2026  
**Repository:** github.com/humanroot  
**Contact:** spec@humanroot.dev

---

## Abstract

This document specifies the Delegation Root Certificate (DRC), a signed, structured, machine-readable record of a human delegation act for autonomous AI agent systems. A DRC provides non-repudiable, scope-bound, propagatable proof that a specific human authorized a specific agent to act within defined constraints.

---

## 1. Motivation

Autonomous AI agents are deployed in production today. They send emails, execute API calls, write to databases, interact with financial systems, and delegate tasks to other agents across providers and frameworks.

The foundational question — **"Who authorized this?"** — has no reliable answer in current systems. Delegation happens through configuration checkboxes, system prompts, API keys, and OAuth scopes. None of these constitute a structured, signed, scope-bound, propagatable record of human authorization.

When a chain of agents acts — Agent A delegating to Agent B delegating to Agent C — the original human intent disappears entirely. The DRC solves this.

---

## 2. Definitions

**Principal** — The human who issues a delegation. Identified by a stable `human_id`.

**Agent** — An autonomous AI system that receives delegated authority.

**DRC** — Delegation Root Certificate. A signed record of one delegation act.

**Root DRC** — A DRC with no parent (`parent_drc_id = null`). Issued directly by a human.

**Sub-delegation** — A DRC issued by an agent to another agent, referencing a parent DRC.

**Chain** — The ordered sequence of DRCs from a root DRC to a leaf DRC.

**Scope** — A string identifying a permitted action type (e.g. `email.read`, `database.write`).

**Revocation** — The act of invalidating a DRC. Cascades to all child DRCs.

---

## 3. DRC Structure

### 3.1 Schema

```
DelegationRootCertificate {
  version:              string       // spec version, e.g. "0.1"
  drc_id:               uuid         // globally unique identifier
  issued_at:            ISO8601      // timestamp of delegation act
  expires_at:           ISO8601      // hard expiry — MUST be after issued_at

  principal {
    human_id:           string       // stable identifier for the delegating human
    identity_method:    string       // "email" | "did" | "oauth_sub" | custom
  }

  agent {
    agent_id:           string       // identifier for the receiving agent
    provider:           string       // e.g. "anthropic" | "openai" | "custom"
  }

  authority {
    scopes:             string[]     // explicit allowed action types
    constraints:        object       // optional: rate limits, targets, etc.
    max_delegation_depth: integer    // max further hops allowed (0 = no sub-delegation)
  }

  revocation_endpoint:  URI | null   // where to check revocation status
  parent_drc_id:        uuid | null  // null = root DRC; else sub-delegation
  root_hash:            SHA256 | null // hash of the root DRC in chain (null on root)
  signature:            JWS | null   // signed by human principal (ES256 recommended)
}
```

### 3.2 Field Rules

- `drc_id` MUST be a UUID v4, globally unique.
- `expires_at` MUST be strictly after `issued_at`.
- `scopes` MUST be a non-empty array of strings.
- `max_delegation_depth` MUST be a non-negative integer.
- `parent_drc_id` MUST be null for root DRCs; MUST reference a valid DRC for sub-delegations.
- `root_hash` MUST be null for root DRCs; MUST equal the SHA-256 of the root DRC's canonical payload for all other DRCs.
- `signature` SHOULD be present for all root DRCs. MAY be present on sub-delegations.

---

## 4. Cryptographic Signature

### 4.1 Recommended Algorithm

ES256 (ECDSA with P-256 curve and SHA-256). Lightweight, widely supported, no external PKI required.

### 4.2 Signing Payload

The signing payload is the canonical JSON serialization of the DRC with the `signature` field excluded:

```
payload = JSON.stringify(drc.unsigned_payload(), sort_keys=True)
signature = ES256.sign(payload, private_key)
```

### 4.3 Verification

```
payload = JSON.stringify(drc.unsigned_payload(), sort_keys=True)
valid = ES256.verify(payload, drc.signature, public_key)
```

### 4.4 Hash

The `root_hash` field contains the SHA-256 hex digest of the canonical JSON payload of the root DRC (the one with `parent_drc_id = null`).

---

## 5. Propagation Model

```
Human issues DRC_0 (root, parent_drc_id=null)
  └─ Agent A receives DRC_0
      └─ Agent A issues DRC_1 (parent=DRC_0, scopes ⊆ DRC_0.scopes)
          └─ Agent B acts
             Action record references DRC_1
             DRC_1.parent_drc_id = DRC_0.drc_id
             DRC_1.root_hash = hash(DRC_0)
             DRC_0.signature = human_signature
             → Chain is fully reconstructible
```

### 5.1 Propagation Invariants

Every implementation MUST enforce:

1. **Every action MUST reference a DRC.**
2. **Every sub-delegation MUST reference its parent DRC.**
3. **No DRC MAY grant more authority than its parent.** (Scopes are strictly subset.)
4. **Child expiry MUST NOT exceed parent expiry.**
5. **`max_delegation_depth` MUST decrement by exactly 1 at each hop.**
6. **`root_hash` MUST be identical across all DRCs in a chain.**

---

## 6. Sub-delegation Rules

A valid sub-delegation from parent DRC `P` to child DRC `C` requires:

```
C.principal        == P.principal           // human origin is preserved
C.scopes           ⊆  P.scopes              // restriction only
C.expires_at       ≤  P.expires_at          // cannot outlive parent
C.max_depth        == P.max_depth - 1       // depth decrements
C.parent_drc_id    == P.drc_id              // linkage
C.root_hash        == P.root_hash ?? hash(P) // chain integrity
P.max_depth        >  0                     // depth must remain
```

Any violation MUST be rejected.

---

## 7. Revocation

### 7.1 Revocation Act

A DRC is revoked by recording its `drc_id` in a revocation store with a timestamp and optional reason.

### 7.2 Cascade

Revocation of a DRC MUST cascade to all descendant DRCs. A revoked parent renders all children invalid regardless of their individual revocation status.

### 7.3 Revocation Check

Systems SHOULD check the `revocation_endpoint` before trusting a DRC. Implementations MAY cache revocation state with a TTL not exceeding the DRC's `expires_at`.

### 7.4 Offline Behavior

When a `revocation_endpoint` is unreachable, implementations SHOULD fail closed (treat as potentially revoked) unless the application explicitly opts into fail-open behavior.

---

## 8. Scope Vocabulary

This specification does not mandate a fixed scope vocabulary. Implementors MAY define their own. A recommended convention:

```
<resource>.<action>

Examples:
  email.read
  email.write
  calendar.read
  calendar.write
  database.read
  database.write
  tool.use
  text.generate
  files.read
  files.write
  api.<service>.<method>
```

A standard vocabulary MAY be defined in a future revision of this spec.

---

## 9. Identity Methods

The `identity_method` field indicates how `human_id` should be interpreted:

| Value | Description |
|---|---|
| `email` | RFC 5321 email address |
| `did` | W3C Decentralized Identifier |
| `oauth_sub` | OAuth 2.0 `sub` claim |
| `github` | GitHub username |
| custom | Any stable identifier the issuer controls |

---

## 10. Relation to Existing Standards

| Standard | What it does | What HumanRoot adds |
|---|---|---|
| OAuth 2.0 | Delegates to an application | Multi-hop agent chain with human origin |
| AWS IAM | Manages permissions within a cloud | Cross-provider, cross-agent propagation |
| eIDAS | Signs static documents | Dynamic delegation with depth and expiry |
| OpenTelemetry | Traces distributed system calls | Human authorization origin in every trace |
| JWT / JWS | Signs arbitrary JSON payloads | DRC-specific semantics and propagation model |

---

## 11. Security Considerations

### 11.1 Key Management

Private keys used to sign DRCs MUST be protected. Compromise of a signing key requires immediate revocation of all DRCs signed with that key.

### 11.2 Scope Creep

Implementations MUST validate scope restriction at sub-delegation time. A child scope that is a superset of its parent's scopes MUST be rejected.

### 11.3 Clock Skew

Implementations SHOULD allow a small clock skew tolerance (recommended: ≤ 30 seconds) when evaluating `expires_at`.

### 11.4 Replay Attacks

The `drc_id` field is a UUID v4 and is globally unique. Implementations SHOULD reject DRCs whose `drc_id` has already been seen in the current session.

---

## 12. Open Questions

The following are deliberately unresolved in v0.1:

- **Identity method:** Should `human_id` support W3C DIDs natively, or remain identity-method-agnostic?
- **Signature scheme:** JWS / ES256 is proposed. Alternative lightweight schemes welcome.
- **Offline verification:** How should systems behave when revocation endpoints are unreachable?
- **Legal equivalence:** Under which jurisdictions does a DRC constitute legally equivalent evidence of consent?
- **Standard scope vocabulary:** Should a normative vocabulary of scope types be defined?
- **Multi-principal DRCs:** Can a DRC require authorization from multiple humans?

---

## 13. Reference Implementation

Python reference implementation: `github.com/humanroot`

```bash
pip install humanroot
```

```python
from humanroot import delegate, sub_delegate, generate_keypair, sign_drc, verify_drc

priv, pub = generate_keypair()

root = delegate(
    human_id="alice@example.com",
    agent_id="agent-a",
    scopes=["email.read", "calendar.write"],
    expires_in="24h",
    signing_key=priv,
)

child = sub_delegate(
    root,
    agent_id="agent-b",
    scopes=["email.read"],
    expires_at=root.expires_at - timedelta(hours=1),
)
```

---

## Changelog

| Version | Date | Notes |
|---|---|---|
| 0.1 | 2026 | Initial working draft |

---

*This is a working draft. Comments, objections, and contributions are welcome.*  
*github.com/humanroot — spec@humanroot.dev*
