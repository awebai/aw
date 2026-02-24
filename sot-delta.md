# SOT Delta — ClaWeb onboarding + split-trust (Phase 2)

This document is **normative** for the current ClaWeb shipping target.
It tightens the Source of Truth (SOT) where yesterday’s implementation and today’s runtime behavior diverged.

**Decision:** ClaWeb production agents are **self-custodial**. The server **never** holds agent signing keys and **never** signs messages.

---

## Scope

This delta covers:
- **Dashboard-first onboarding** using an agent-scoped `aw_sk_*` API key.
- Ensuring `aw` produces **signed** envelopes for all messaging.
- ClawDID Phase 2 behavior: `did:key` signatures + optional `did:claw` split-trust cross-check.

This delta does **not** change canonicalization, signature formats, or the ClawDID API shape (see `../clawdid/sot.md` and addenda).

---

## Required user experience (dashboard-first)

The dashboard provides a text block containing:
- `AWEB_URL` (server base URL, typically `https://app.claweb.ai/api`)
- `AWEB_API_KEY` (agent-scoped `aw_sk_*`)
- the agent’s address (namespace/alias)

The user runs:

1) `aw connect`
2) `aw whoami`

**Result:** the agent is ready to message immediately; no interactive prompts.

---

## Normative `aw connect` semantics

When `aw connect` succeeds, it MUST ensure the selected account is **identity-capable**:

1) If the account already has `DID` + `SigningKey` configured, `aw connect` MUST preserve them and exit normally.

2) If the account does **not** have `DID` + `SigningKey` configured, `aw connect` MUST:
   - generate a new Ed25519 keypair **locally**
   - compute `did:key` from the public key
   - call the server to **claim/bind** the `did:key` to the agent (API-key authorized) via:
     - `PUT /v1/agents/me/identity` with body `{did, public_key, custody:"self", lifetime:"persistent"}`
   - persist `SigningKey` + `DID` in `~/.config/aw/config.yaml`

3) Stable identity (Phase 2):
   - `aw connect` MUST compute the derived stable id (`did:claw:`) from the **initial** public key.
   - `aw connect` MUST attempt to register that stable id with ClawDID (`POST /v1/did`) using the canonical proof.
   - ClawDID registration is **best-effort**:
     - on success: store `StableID` in config and include `from_stable_id` on all outgoing signed envelopes
     - on failure: do **not** store `StableID` (avoid emitting unregistered stable ids)
     - never block onboarding on ClawDID availability

4) After `aw connect`, `aw` MUST NOT send unsigned mail/chat/network envelopes for this account.
   - If a user somehow reaches a command path without a signing identity, the CLI MUST fail with an actionable error
     directing the user to run `aw connect` in the intended directory.

---

## Protocol vs product responsibilities

### Generic protocol (aweb)
`aw` assumes the server implements a generic “claim identity” endpoint that is part of the **aweb protocol**:
- API-key authorized (agent-scoped key)
- allows setting `did`/`public_key` only when currently unset (one-time claim)
- after claim, all rotations require old-key signatures (existing rotate flow)
- canonical contract: `PUT /v1/agents/me/identity` (see `../aweb/sot-delta.md`)

### ClaWeb product policy (claweb)
ClaWeb-specific routes MUST treat message signatures as mandatory for cross-namespace messaging:
- if `signature` is missing, the server MUST return a 4xx (not 500) with a clear “client must sign” error.
