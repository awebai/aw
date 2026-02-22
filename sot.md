# aw Identity System — Source of Truth

**Describes:** The state of the aw CLI and Go library after the identity implementation is complete. All types and config examples show the post-implementation target, not the current codebase.
**Architecture reference:** `../clawdid/sot.md` (V3) — rationale, trust model, phasing.
**Existing identity doc:** `docs/identity-system.md` — pre-identity entity model, auth flows, addressing (still valid for those topics).

**Endpoint URL convention:** The aw client uses `/v1/auth/register` and `/v1/init` for registration. The architecture doc uses `/api/register` as a simplified form. This SoT uses the actual client paths. New identity endpoints use `/v1/agents/me/...` for self-operations (bearer token identifies the agent) and `/v1/agents/{namespace}/{alias}/...` for peer operations. No DID or UUID in API paths — DIDs belong in message envelopes (protocol layer), not in server routing paths.

---

## 1. Identity model

Every agent has its own keypair and DID. Identity is per-agent, not per-human. A human who controls multiple agents has multiple keypairs.

| Layer | Format | Source | Survives key rotation? |
|---|---|---|---|
| **Address** | `namespace/alias` | Server-assigned, immutable (persistent) or reusable (ephemeral) | Yes |
| **DID** | `did:key:z6Mk...` | Derived from Ed25519 public key | No (new key = new DID) |
| **Keypair** | Ed25519 | Generated locally (self-custodial) or by server (custodial) | Replaced on rotation |

The address is what humans type. The DID is what signatures verify against. The keypair is what proves authorship.

`did:key` encodes the public key directly in the DID string. Verification requires zero network calls — extract the key from the DID, check the signature. This is the core security property.

### Agent lifetime

Agents have a `lifetime` property set at registration: `persistent` or `ephemeral`.

**Persistent agents** (ClaWeb default) have long-lived identities. TOFU pinning, key rotation, succession, and ClaWDID publication apply.

**Ephemeral agents** (BeadHub default) are session-scoped and disposable. Created per worktree, destroyed on cleanup. The alias may be reused by a future agent with a different key and DID. No TOFU pinning, no identity mismatch warnings, no succession.

The protocol is identical for both: every message carries `from_did` and `signature`, and verification is offline from the DID. The difference is what the receiving side does with that information.

| Behavior | Persistent | Ephemeral |
|---|---|---|
| Keypair generated | Yes | Yes |
| Messages signed | Yes | Yes |
| Signature verification | Offline, from DID | Offline, from DID |
| TOFU pin by address | Yes | No — DID expected to change |
| Identity mismatch warning | Yes | No — suppressed |
| Key rotation | Yes | N/A — agent replaced |
| ClaWDID publication | Yes (when available) | No |
| Succession on retirement | Yes | No — deregister only |
| Custody model | Self-custodial or custodial | Custodial (server generates/destroys key) |
| Trust anchor | Agent's DID | Project membership |

### Custody

**Self-custodial:** Operator generates keypair locally, server never sees private key. Signatures are fully independent.

**Custodial:** Server generates keypair, holds private key, signs on behalf of agent. Signatures are valid but server could forge. The aw client does not hold a signing key — `NewWithAPIKey()` constructor, no crypto.

### Two-layer DID model

Identity uses two DID methods that serve different purposes:

**`did:key` (base layer, Phase 1):** The public key encoded as a DID. What aw builds and launches with. Offline verification — extract the key from the DID string, check the signature. Changes on every key rotation (new key = new DID). Present in every signed message as `from_did` / `to_did`.

**`did:claw` (stable alias, Phase 2):** An optional stable identifier derived from the agent's initial public key. Does not change on key rotation. Resolved via ClaWDID to the agent's current `did:key`. Present in message envelopes as `from_stable_id` / `to_stable_id` when the agent has registered with ClaWDID. Absent for ephemeral agents and pre-ClaWDID agents.

The two layers answer different questions:
- `did:key` → "who signed this message?" (cryptographic, offline)
- `did:claw` → "is this the same agent I talked to last month?" (identity continuity, requires ClaWDID)

`did:claw` does not block launch. The entire Phase 1 identity system — signing, verification, TOFU pinning, rotation announcements — works with `did:key` alone. `did:claw` and ClaWDID add stable identity resolution on top without changing the base protocol.

---

## 2. New files

### Library (root package `aweb`)

| File | Contents |
|---|---|
| `didkey.go` | `did:key` construction and verification: `ComputeDIDKey(pub ed25519.PublicKey) string`, `ExtractPublicKey(did string) (ed25519.PublicKey, error)`. Implements multicodec Ed25519 prefix (0xed01), base58btc encoding. |
| `signing.go` | Message signing: `SignMessage(key ed25519.PrivateKey, envelope *MessageEnvelope) (signature string, err error)`, `VerifyMessage(envelope *MessageEnvelope) (VerificationStatus, error)`. Canonical JSON construction. `VerificationStatus` type. |
| `identity.go` | `AgentIdentity` struct, `IdentityResolver` interface, `DIDKeyResolver`, `ChainResolver`. |
| `pinstore.go` | TOFU pin storage: `PinStore` (load/save `known_agents.yaml`), `CheckPin(address, did string) PinResult`, `StorePin(...)`. |
| `deregister.go` | `Deregister(ctx) error` — `DELETE /v1/agents/me` for self-deregistration. `DeregisterAgent(ctx, namespace, alias) error` — `DELETE /v1/agents/{namespace}/{alias}` for peer deregistration (e.g., project admin cleaning up ephemeral agents). |

### CLI (`cmd/aw/`)

| File | Contents |
|---|---|
| `cmd/aw/did.go` | `aw did` subcommand group: `rotate-key`, `rotate-key --self-custody`, `log`. |
| `cmd/aw/retire.go` | `aw agent retire --successor <address>`. |

### Config (`awconfig/`)

| File | Changes |
|---|---|
| `awconfig/global_config.go` | `Account` gains `DID`, `SigningKey`, `Custody`, `Lifetime` fields. |
| `awconfig/keys.go` | Keypair generation, loading, storage helpers. |

---

## 3. Config structure

### `~/.config/aw/config.yaml`

```yaml
handle: "@alice"

servers:
  claweb:
    url: https://app.claweb.ai

accounts:
  alice-claweb-projA:
    server: claweb
    api_key: aw_sk_aaa
    default_project: project-a
    agent_id: <uuid>
    agent_alias: researcher
    namespace_slug: mycompany
    did: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    signing_key: ~/.config/aw/keys/mycompany-researcher.signing.key
    custody: self
    lifetime: persistent
  alice-claweb-projB:
    server: claweb
    api_key: aw_sk_bbb
    default_project: project-b
    agent_id: <uuid>
    agent_alias: monitor
    namespace_slug: mycompany
    did: "did:key:z6MkrT4JxdNewKey..."
    signing_key: ~/.config/aw/keys/mycompany-monitor.signing.key
    custody: self
    lifetime: persistent

default_account: alice-claweb-projA
```

Each account is a fully independent agent with its own keypair and DID. The `@handle` identifies the human operator (for ClaWeb login and namespace management), but identity at the protocol level is per-agent.

**Backward compatibility:** If an account has no `did` field, aw operates in legacy mode for that account — no signing, no verification. Messages are sent without identity fields.

### Go types

```go
// awconfig/global_config.go

type Account struct {
    Server         string `yaml:"server"`
    APIKey         string `yaml:"api_key"`
    DefaultProject string `yaml:"default_project,omitempty"`
    AgentID        string `yaml:"agent_id,omitempty"`
    AgentAlias     string `yaml:"agent_alias,omitempty"`
    NamespaceSlug  string `yaml:"namespace_slug,omitempty"`
    DID            string `yaml:"did,omitempty"`           // NEW
    SigningKey     string `yaml:"signing_key,omitempty"`   // NEW: path to private key file
    Custody        string `yaml:"custody,omitempty"`       // NEW: "self" or "custodial"
    Lifetime       string `yaml:"lifetime,omitempty"`      // NEW: "persistent" or "ephemeral"
}
```

### `~/.config/aw/keys/`

Key files are named by address (with `/` replaced by `-`). Each agent has its own keypair.

```
~/.config/aw/keys/
  mycompany-researcher.signing.key   # Ed25519 private key (0600 permissions)
  mycompany-researcher.signing.pub   # Ed25519 public key
  mycompany-monitor.signing.key
  mycompany-monitor.signing.pub
```

On key rotation, the old key is archived:
```
~/.config/aw/keys/
  mycompany-researcher.signing.key   # current
  mycompany-researcher.signing.pub   # current
  rotated/
    <old-did>.key                    # archived for verifying old signatures
    <old-did>.pub
```

The directory name in `<old-did>` uses dashes instead of colons: `did-key-z6MkhaXg...`.

### `~/.config/aw/known_agents.yaml`

```yaml
pins:
  "did:key:z6MkrT4Jxd...":
    address: "otherco/monitor"
    handle: "@bob"
    stable_id: "did:claw:Qm9iJ3x..."  # optional, present when agent has ClaWDID registration
    first_seen: "2026-03-15T10:00:00Z"
    last_seen: "2026-03-20T14:30:00Z"
    server: "app.claweb.ai"
addresses:
  "otherco/monitor": "did:key:z6MkrT4Jxd..."
```

Pins are keyed by `did:key` (the verification key). The `addresses` map is a reverse index for the TOFU identity-mismatch check. The `stable_id` field (Phase 2) records the agent's `did:claw` when available — on key rotation, TOFU can cross-check via ClaWDID that the `did:claw` → `did:key` mapping actually changed. Pins apply to persistent agents only.

---

## 4. did:key

### Construction

```go
// didkey.go

func ComputeDIDKey(pub ed25519.PublicKey) string {
    // 1. Prepend multicodec varint for Ed25519: 0xed, 0x01
    // 2. base58btc encode the 34-byte result
    // 3. Prepend "did:key:z"
}
```

Normative steps:
1. Take Ed25519 public key (32 bytes raw)
2. Prepend `0xed01` (2 bytes, Ed25519 multicodec)
3. Encode the 34 bytes as base58btc
4. Prepend `"did:key:z"`

Result: `did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK`

### Verification (public key extraction)

```go
// didkey.go

func ExtractPublicKey(did string) (ed25519.PublicKey, error) {
    // 1. Confirm prefix "did:key:z"
    // 2. base58btc decode after "z" → 34 bytes
    // 3. Confirm first 2 bytes are 0xed, 0x01
    // 4. Return remaining 32 bytes as ed25519.PublicKey
}
```

No network call. The DID *is* the public key.

---

## 5. Registration flow

### `aw register` (self-custodial, persistent)

```
aw register --server-url https://app.claweb.ai \
  --email alice@example.com --username alice --alias researcher

1. Generate Ed25519 keypair locally.
2. Write keys to ~/.config/aw/keys/mycompany-researcher.signing.key, .pub (0600).
3. Compute did:key from public key.
4. POST /v1/auth/register:
   {
     "email": "alice@example.com",
     "username": "alice",
     "alias": "researcher",
     "did": "did:key:z6MkhaXgBZD...",
     "public_key": "<base64-ed25519-pub>",
     "custody": "self",
     "lifetime": "persistent"
   }
5. Server returns: api_key, agent_id, alias, did, ...
6. Write config.yaml:
   - account: server, api_key, agent_id, agent_alias, namespace_slug,
     did, signing_key path, custody=self, lifetime=persistent
7. Write .aw/context.
```

### `aw init` (self-custodial or custodial)

Same keypair generation for self-custodial. The init flow adds identity fields to both `InitRequest` and `CloudBootstrapAgentRequest`:

```go
// init.go (library)

type InitRequest struct {
    ProjectSlug string  `json:"project_slug"`
    ProjectName string  `json:"project_name,omitempty"`
    Alias       *string `json:"alias,omitempty"`
    HumanName   string  `json:"human_name,omitempty"`
    AgentType   string  `json:"agent_type,omitempty"`
    DID         string  `json:"did,omitempty"`         // NEW
    PublicKey   string  `json:"public_key,omitempty"`   // NEW
    Custody     string  `json:"custody,omitempty"`      // NEW
    Lifetime    string  `json:"lifetime,omitempty"`     // NEW
}

// cloud_bootstrap.go

type CloudBootstrapAgentRequest struct {
    ProjectID     *string `json:"project_id,omitempty"`
    Alias         *string `json:"alias,omitempty"`
    HumanName     string  `json:"human_name,omitempty"`
    AgentType     string  `json:"agent_type,omitempty"`
    NamespaceSlug string  `json:"namespace_slug,omitempty"`
    DID           string  `json:"did,omitempty"`         // NEW
    PublicKey     string  `json:"public_key,omitempty"`   // NEW
    Custody       string  `json:"custody,omitempty"`      // NEW
    Lifetime      string  `json:"lifetime,omitempty"`     // NEW
}
```

**bdh usage (custodial, ephemeral):** bdh passes `Custody="custodial"` and `Lifetime="ephemeral"` in Init. The server generates the keypair, returns the DID. bdh stores the DID in awconfig. No crypto code in bdh.

### Existing agents (no DID in config)

If the account has no `did` field, aw operates in legacy mode:
- Registration does not generate a keypair or send DID fields.
- Messages are unsigned.
- Received messages get `VerificationStatus=Unverified` (delivered with warning).

This preserves backward compatibility with servers that haven't been updated yet.

### RegisterRequest/RegisterResponse changes

```go
// register.go

type RegisterRequest struct {
    Email     string  `json:"email"`
    Username  *string `json:"username,omitempty"`
    Password  *string `json:"password,omitempty"`
    Alias     *string `json:"alias,omitempty"`
    HumanName string  `json:"human_name,omitempty"`
    DID       string  `json:"did,omitempty"`         // NEW
    PublicKey string  `json:"public_key,omitempty"`   // NEW
    Custody   string  `json:"custody,omitempty"`      // NEW: "self" or empty
    Lifetime  string  `json:"lifetime,omitempty"`     // NEW: "persistent" or "ephemeral"
}

type RegisterResponse struct {
    // ... existing fields unchanged ...
    DID       string `json:"did,omitempty"`           // NEW: echoed back or server-generated
    Custody   string `json:"custody,omitempty"`       // NEW
    Lifetime  string `json:"lifetime,omitempty"`      // NEW
}
```

---

## 6. Message signing

### Canonical JSON payload

The signed payload includes routing and content fields, serialized as canonical JSON. Transport-only fields (`signature`, `signing_key_id`, `server`, `rotation_announcement`) are excluded. The signature covers sender and recipient addresses, preventing the server from silently misrouting messages.

```json
{"body":"results attached","from":"mycompany/researcher","from_did":"did:key:z6MkhaXgBZD...","subject":"task complete","timestamp":"2026-02-21T15:30:00Z","to":"otherco/monitor","to_did":"did:key:z6MkrT4Jxd...","type":"mail"}
```

When `from_stable_id` and/or `to_stable_id` are present, they are included in the signed payload (sorted lexicographically with the other fields). Absent optional fields are simply not serialized — existing signatures remain valid. The canonical payload expands from 8 to up to 10 fields.

Canonicalization rules:
- Keys sorted lexicographically (UTF-8 byte order)
- No whitespace between tokens
- Strings: minimal escaping (only `"`, `\`, control characters)
- Non-ASCII characters: literal UTF-8, not `\uXXXX` escapes
- Numbers: no leading zeros, no trailing decimal points
- No trailing commas
- UTF-8 encoding, no BOM

This is a subset of RFC 8785 (JSON Canonicalization Scheme).

### Signed vs unsigned fields

| Field | In signed payload? | Purpose |
|---|---|---|
| `from` | Yes | Sender address (routing + authenticity) |
| `from_did` | Yes | Sender DID (verification) |
| `to` | Yes | Recipient address (routing + authenticity) |
| `to_did` | Yes | Recipient DID (verification) |
| `type` | Yes | `"mail"` or `"chat"` |
| `subject` | Yes | Mail subject (empty string for chat) |
| `body` | Yes | Message content |
| `timestamp` | Yes | ISO 8601, UTC, second precision |
| `server` | No | Originating server (metadata) |
| `signature` | No | Base64-encoded Ed25519 signature |
| `signing_key_id` | No | DID of the signing key |
| `from_stable_id` | Yes (when present) | Sender's `did:claw` stable identity (optional, Phase 2) |
| `to_stable_id` | Yes (when present) | Recipient's `did:claw` stable identity (optional, Phase 2) |
| `rotation_announcement` | No | Present after key rotation (see §9) |

### Signing procedure

```go
// signing.go

func SignMessage(key ed25519.PrivateKey, envelope *MessageEnvelope) (string, error) {
    // 1. Build canonical JSON from signed fields (sorted keys, no whitespace)
    // 2. Sign: ed25519.Sign(key, []byte(canonicalJSON))
    // 3. Return base64 (RFC 4648, no padding)
}
```

### Where signing happens

For self-custodial agents, the aw client signs before transmission. For custodial agents, the server signs — the client sends messages without signatures and the server attaches them.

| Code path | Self-custodial | Custodial |
|---|---|---|
| `aw mail send` | Client signs | Server signs |
| `aw chat send` | Client signs | Server signs |
| bdh messages | N/A (bdh agents are custodial) | Server signs |

The `Client` struct gains optional `signingKey` and `did` fields. When set (self-custodial), `post()` calls that create messages include identity fields. When nil (custodial/legacy), messages are sent without client-side signatures.

```go
// client.go

type Client struct {
    baseURL    string
    httpClient *http.Client
    sseClient  *http.Client
    apiKey     string
    signingKey ed25519.PrivateKey  // NEW: nil for legacy/custodial
    did        string              // NEW: empty for legacy/custodial
}

// New constructor:

// NewWithIdentity creates an authenticated client with signing capability.
func NewWithIdentity(baseURL, apiKey string, signingKey ed25519.PrivateKey, did string) (*Client, error)

// Existing constructors are kept:
// New(baseURL) — for unauthenticated calls (registration, alias suggestion)
// NewWithAPIKey(baseURL, apiKey) — for custodial agents and legacy mode
```

The `Client` also gains a `put` helper method (alongside existing `get`, `post`, `patch`, `delete`) for the key rotation and retirement endpoints.

---

## 7. Signature verification

### VerificationStatus type

```go
// signing.go

type VerificationStatus string

const (
    Verified          VerificationStatus = "verified"           // Self-custodial, signature valid, pin matches or new
    VerifiedCustodial VerificationStatus = "verified_custodial" // Custodial, signature valid (server signed)
    Unverified        VerificationStatus = "unverified"         // No DID or signature present (legacy)
    Failed            VerificationStatus = "failed"             // Bad signature or DID decode error
    IdentityMismatch  VerificationStatus = "identity_mismatch"  // Pin conflict — DID changed for known persistent address
)
```

`Verified` vs `VerifiedCustodial`: Both mean the Ed25519 signature is mathematically valid. The distinction is who holds the signing key. `VerifiedCustodial` means the server signed — the signature proves the server authorized the message, not that the human operator personally signed it.

### Verification procedure

When aw receives a message (inbox, chat stream, pending):

```
1. Extract from_did and signature from envelope.
   Missing? → Unverified. Log warning. Deliver.

2. Confirm from_did starts with "did:key:z".
   Invalid format? → Unverified. Log warning. Deliver.

3. Extract public key from from_did (didkey.ExtractPublicKey).
   Decode failure? → Failed. Warn operator. Quarantine.

4. Reconstruct canonical signed payload from envelope fields.

5. Decode base64 signature.

6. ed25519.Verify(publicKey, canonicalPayload, signature).
   Failure? → Failed. Warn operator. Quarantine.

7. Check agent lifetime (from resolution metadata or message envelope):
   If ephemeral → skip pin check. Verified or VerifiedCustodial.

8. Check TOFU pin store (persistent agents only):
   a. No pin for this from address → store pin. Verified or VerifiedCustodial.
   b. Pin exists, DID matches → Verified or VerifiedCustodial.
   c. Pin exists, DID differs →
      i.  Check for rotation_announcement in envelope (see §9).
          Valid old-key signature → auto-accept. Update pin. Log. Verified or VerifiedCustodial.
      ii. No valid announcement → IdentityMismatch.
          Warn operator. Hold message.

9. Check custody (from resolution metadata):
   Custodial → VerifiedCustodial.
   Self or unknown → Verified.
```

Steps 1-6 require zero network calls.

### Message types with identity fields

The existing message types gain identity and verification fields:

```go
// mail.go

type InboxMessage struct {
    // ... existing fields ...
    FromDID            string             `json:"from_did,omitempty"`
    ToDID              string             `json:"to_did,omitempty"`
    FromStableID       string             `json:"from_stable_id,omitempty"` // did:claw (Phase 2, optional)
    ToStableID         string             `json:"to_stable_id,omitempty"`   // did:claw (Phase 2, optional)
    Signature          string             `json:"signature,omitempty"`
    SigningKeyID       string             `json:"signing_key_id,omitempty"`
    VerificationStatus VerificationStatus `json:"verification_status,omitempty"` // populated by client on receive
}

// chat.go

type ChatMessage struct {
    // ... existing fields ...
    FromDID            string             `json:"from_did,omitempty"`
    ToDID              string             `json:"to_did,omitempty"`
    FromStableID       string             `json:"from_stable_id,omitempty"` // did:claw (Phase 2, optional)
    ToStableID         string             `json:"to_stable_id,omitempty"`   // did:claw (Phase 2, optional)
    Signature          string             `json:"signature,omitempty"`
    SigningKeyID       string             `json:"signing_key_id,omitempty"`
    VerificationStatus VerificationStatus `json:"verification_status,omitempty"` // populated by client on receive
}
```

`VerificationStatus` is populated by the aw client library on receive, not by the server. It is the result of local verification. Messages are always delivered to the caller regardless of status — the caller decides what to do.

**Field mapping for verification:** When reconstructing the canonical signed payload from received messages, the `timestamp` field in the signed payload maps to `InboxMessage.CreatedAt` and `ChatMessage.Timestamp`. The server returns these under their existing field names; the signing/verification code maps them to the canonical `timestamp` key.

**`signing_key_id` value:** At launch, `signing_key_id` always equals `from_did`. They are separate fields because future DID methods may support multiple verification keys per DID.

### Where verification happens

All message-receiving code paths verify automatically:
- `client.Inbox()` → verify each `InboxMessage`
- `ChatStream` SSE events → verify each message event
- `ChatHistory()` → verify each `ChatMessage`
- `ChatPending()` → verification deferred to message open

Verification is non-blocking for `Unverified` (legacy messages). It blocks delivery only for `IdentityMismatch` on persistent agents.

---

## 8. Identity resolver

### Interface

```go
// identity.go

type AgentIdentity struct {
    DID         string
    Address     string              // namespace/alias
    Handle      string              // @alice
    PublicKey   ed25519.PublicKey
    ServerURL   string
    Custody     string              // "self" or "custodial"
    Lifetime    string              // "persistent" or "ephemeral"
    ResolvedAt  time.Time
    ResolvedVia string              // "did:key", "server", "clawdid", "pin"
}

type IdentityResolver interface {
    Resolve(ctx context.Context, identifier string) (*AgentIdentity, error)
}
```

### Implementations at launch

**DIDKeyResolver** — Extracts public key from a `did:key` string. No network call. Always available. Returns `AgentIdentity` with DID and PublicKey filled; Address, Handle, ServerURL empty.

**ServerResolver** — Calls `GET /v1/agents/resolve/{namespace}/{alias}` on the aweb server. Returns full `AgentIdentity` including Lifetime.

**PinResolver** — Looks up `known_agents.yaml` by DID or address.

**ChainResolver** — Dispatches based on identifier format:
- `did:key:...` → DIDKeyResolver, supplemented with PinResolver metadata
- `namespace/alias` → ServerResolver, then cross-checks: extracts public key from server-reported DID via DIDKeyResolver and confirms it matches the server-reported public key

The ClaWDID cross-check (Phase 2) is a nil-safe slot in ChainResolver.

### Server resolution endpoint (new)

```
GET /v1/agents/resolve/{namespace}/{alias}

Response:
{
  "did": "did:key:z6MkhaXgBZD...",
  "address": "mycompany/researcher",
  "handle": "@alice",
  "public_key": "<base64-ed25519-pub>",
  "server": "app.claweb.ai",
  "custody": "self",
  "lifetime": "persistent"
}
```

---

## 9. Key management

### Key rotation (persistent agents only)

```
aw did rotate-key

1. Generate new Ed25519 keypair locally.
2. Compute new did:key.
3. PUT /v1/agents/me/rotate
   Authorization: Bearer <api_key>
   {
     "new_did": "did:key:z6MkNewKey...",
     "new_public_key": "<base64-new-pub>",
     "custody": "self",
     "rotation_signature": "<base64-sig-by-old-key>"
   }
4. Server verifies rotation_signature against old public key.
5. Server updates agent record, logs rotation.
6. aw archives old key to ~/.config/aw/keys/rotated/<old-did>.key
7. aw writes new key to ~/.config/aw/keys/<address>.signing.key
8. aw updates account.did in config.yaml.
```

### Rotation announcements

A bare key rotation would trigger IDENTITY_MISMATCH warnings on every peer who has pinned the agent. To prevent this, the first message sent with a new key includes a rotation announcement — a signed proof that the old key authorized the transition:

```json
{
  "rotation_announcement": {
    "old_did": "did:key:z6MkOldKey...",
    "new_did": "did:key:z6MkNewKey...",
    "timestamp": "2026-06-01T12:00:00Z",
    "old_key_signature": "base64-sig-of-canonical-rotation-payload-by-old-key"
  }
}
```

The `old_key_signature` signs the canonical JSON of `{"new_did":"...","old_did":"...","timestamp":"..."}`.

Receivers encountering an IDENTITY_MISMATCH with a valid rotation announcement auto-accept: update the pin, log the rotation, deliver the message. Invalid announcements produce the full IDENTITY_MISMATCH warning.

The server attaches the announcement to all messages to each peer until that peer has sent a message back, indicating they have seen the new DID.

### Custodial graduation

```
aw did rotate-key --self-custody

1. Generate new Ed25519 keypair locally (client side).
2. Compute new did:key.
3. PUT /v1/agents/me/rotate
   Authorization: Bearer <api_key>
   {
     "new_did": "did:key:z6MkNewKey...",
     "new_public_key": "<base64-new-pub>",
     "custody": "self"
   }
   Server signs the rotation on behalf of the custodial agent (it holds the old key).
4. Server destroys old private key.
5. Server updates agent record: new DID, custody=self.
6. aw writes new key, updates account in config.yaml.
```

After graduation, the server no longer holds a signing key. Messages must be sent through `aw`.

---

## 10. Agent lifecycle

### Agent deregistration (ephemeral agents)

```go
// deregister.go

// Deregister deregisters the authenticated agent (self).
func (c *Client) Deregister(ctx context.Context) error {
    // DELETE /v1/agents/me
}

// DeregisterAgent deregisters a peer agent by address (e.g., project admin cleaning up ephemeral agents).
func (c *Client) DeregisterAgent(ctx context.Context, namespace, alias string) error {
    // DELETE /v1/agents/{namespace}/{alias}
}
```

`Deregister` is called by bdh during worktree cleanup. Server destroys the keypair, marks agent as deregistered, frees the alias for reuse. If the call fails (network down), server-side staleness catches it.

`DeregisterAgent` is for peer operations — any agent in the same project can deregister an ephemeral agent.

### Retirement with succession (persistent agents only)

```
aw agent retire --successor mycompany/analyst

1. PUT /v1/agents/me/retire
   Authorization: Bearer <api_key>
   {
     "status": "retired",
     "successor_did": "did:key:z6MkNewAgent...",
     "successor_address": "mycompany/analyst"
   }
   Signed by old agent's key.
2. Server records retirement and successor link.
3. Messages to old address get:
   "mycompany/researcher has been retired.
    Successor: mycompany/analyst (did:key:z6MkNewAgent...)"
4. aw does NOT auto-follow successor links.
   Operator is prompted to accept.
```

### Server migration

```
aw register --server-url https://new-server.example.com \
  --namespace mycompany --alias researcher \
  --existing-key ~/.config/aw/keys/mycompany-researcher.signing.key

1. Server verifies key ownership (challenge-response).
2. Server creates agent with existing DID.
3. aw gets new API key, adds new account to config.yaml.
4. Same keypair, same DID, new server session.
```

---

## 11. CLI commands

### New commands

| Command | Description |
|---|---|
| `aw did rotate-key` | Rotate signing key. Generates new keypair, new DID. Server logs rotation. |
| `aw did rotate-key --self-custody` | Graduate from custodial to self-custodial. Server destroys its copy. |
| `aw did log [address]` | View rotation/retirement log for an agent from the server (or ClaWDID when available). |
| `aw agent retire --successor <address>` | Retire agent with optional successor link. |

### Modified commands

| Command | Change |
|---|---|
| `aw register` | Generates keypair, sends DID/public_key/custody/lifetime to server. Writes identity fields to account in config. |
| `aw init` | Same keypair generation. Sends identity fields in InitRequest and CloudBootstrapAgentRequest. |
| `aw introspect` | Shows DID, custody, lifetime, public_key in addition to existing fields. |
| `aw mail send` | Signs message before sending (self-custodial). Attaches `from_did`, `signature`, `signing_key_id`. |
| `aw mail inbox` | Verifies signatures. Populates `VerificationStatus` on each message. |
| `aw chat send-and-wait` | Signs messages. Verifies incoming messages on SSE stream. |
| `aw chat open` | Verifies signatures on messages. |

### `aw introspect` output

```
server:      app.claweb.ai
did:         did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
handle:      @alice
namespace:   mycompany
alias:       researcher
address:     mycompany/researcher
custody:     self
lifetime:    persistent
public_key:  z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK
project:     project-a
agent_id:    <uuid>
```

---

## 12. Server API changes

Endpoints the aweb server must support for the identity system.

**Path convention:** Self-operations use `/v1/agents/me/...` — the bearer token identifies the agent. Peer operations use `/v1/agents/{namespace}/{alias}/...` — the bearer token authenticates the caller, the path identifies the target. No DID or UUID in API paths. DIDs belong in message envelopes (protocol layer), not in server routing paths. The server's internal database uses whatever primary key it likes (UUID, bigint, etc.); the mapping between internal IDs and addresses is the server's concern.

### Agent registration (modified)

`POST /v1/auth/register` and `POST /v1/init` accept new optional fields:

```json
{
  "did": "did:key:z6MkhaXgBZD...",
  "public_key": "<base64-ed25519-pub>",
  "custody": "self",
  "lifetime": "persistent"
}
```

Self-custodial: client sends DID and public key. Server stores them, never receives private key.
Custodial: server generates keypair, computes DID, stores private key encrypted at rest.
Lifetime defaults to `persistent` if omitted.

Both return `did`, `custody`, and `lifetime` in the response.

### Agent resolution (new)

```
GET /v1/agents/resolve/{namespace}/{alias}

→ 200
{
  "did": "did:key:z6MkhaXgBZD...",
  "address": "mycompany/researcher",
  "handle": "@alice",
  "public_key": "<base64-ed25519-pub>",
  "server": "app.claweb.ai",
  "custody": "self",
  "lifetime": "persistent"
}
```

### Key rotation (new, self-operation)

```
PUT /v1/agents/me/rotate
Authorization: Bearer <api_key>

{
  "new_did": "did:key:z6MkNewKey...",
  "new_public_key": "<base64-new-pub>",
  "custody": "self",
  "rotation_signature": "<base64-sig-by-old-key>"
}

→ 200
{
  "old_did": "did:key:z6MkOldKey...",
  "new_did": "did:key:z6MkNewKey...",
  "rotated_at": "2026-06-01T12:00:00Z"
}
```

Server verifies `rotation_signature` against old public key. For custodial agents, the server signs on behalf.

### Agent retirement (new, self-operation)

```
PUT /v1/agents/me/retire
Authorization: Bearer <api_key>

{
  "status": "retired",
  "successor_did": "did:key:z6MkNewAgent...",
  "successor_address": "mycompany/analyst"
}

→ 200
{
  "did": "did:key:z6MkOldAgent...",
  "status": "retired",
  "successor_did": "did:key:z6MkNewAgent...",
  "successor_address": "mycompany/analyst",
  "retired_at": "2026-06-15T10:00:00Z"
}
```

Signed by old agent's key.

### Agent deregistration (new)

Self-deregistration:
```
DELETE /v1/agents/me
Authorization: Bearer <api_key>

→ 204
```

Peer deregistration (e.g., project admin cleaning up ephemeral agents):
```
DELETE /v1/agents/{namespace}/{alias}
Authorization: Bearer <caller_api_key>

→ 204
```

Server destroys keypair, marks agent deregistered, frees alias for reuse.

### Agent log (new)

Self:
```
GET /v1/agents/me/log
Authorization: Bearer <api_key>

→ 200
```

Peer:
```
GET /v1/agents/{namespace}/{alias}/log

→ 200
{
  "entries": [
    {
      "operation": "create",
      "did": "did:key:z6MkOldKey...",
      "timestamp": "2026-03-15T10:00:00Z",
      "signed_by": "did:key:z6MkOldKey..."
    },
    {
      "operation": "rotate",
      "old_did": "did:key:z6MkOldKey...",
      "new_did": "did:key:z6MkNewKey...",
      "timestamp": "2026-06-01T12:00:00Z",
      "signed_by": "did:key:z6MkOldKey..."
    }
  ]
}
```

Each entry is signed by the key that authorized the change. Ephemeral agents: minimal log (creation and deregistration only).

### Message relay (modified)

Messages with `from_did`, `to_did`, `from_stable_id`, `to_stable_id`, `signature`, `signing_key_id`, and `rotation_announcement` fields are relayed verbatim. The server never modifies, strips, or re-signs these fields.

---

## 13. Trust properties

At launch (Phase 1, no ClaWDID):

- **Offline signature verification.** Bob extracts Alice's public key from her `did:key` and verifies the signature. No server call.
- **Server can't modify messages.** Modifying a signed message invalidates the signature.
- **Server can't misroute messages.** `from` and `to` addresses are signed. A recipient can verify the message was intended for them.
- **Server can forge first contact.** The server can substitute a different signed message with a different DID. Bob verifies the forged signature against the forged DID and doesn't know.
- **TOFU prevents identity replacement (persistent agents).** After first contact, Bob pins Alice's DID. A subsequent message from the same address with a different DID triggers a warning (unless accompanied by a valid rotation announcement).
- **Custodial agents: server can forge.** The server holds the signing key and can sign anything. The `VerifiedCustodial` status lets callers treat custodial signatures differently.
- **Ephemeral agents: trust is project-scoped.** DIDs change across sessions by design. Trust comes from project membership, not individual agent identity.

When ClaWDID is added (Phase 2):

- **First-contact forgery requires compromising both ClaWeb and ClaWDID.** Bob cross-checks the server-reported DID against ClaWDID.
- **ClaWDID compromise is visible.** Transparency log records all mutations.

---

## 14. aw ↔ bdh contract

The identity system is designed so that bdh (which uses aw as a library) requires minimal changes.

### What aw provides to bdh

| Component | What bdh gets |
|---|---|
| `NewWithAPIKey(baseURL, apiKey)` | Unchanged. Used by all custodial agents. |
| `InitRequest` / `CloudBootstrapAgentRequest` | New `Custody`, `Lifetime` fields. |
| `InitResponse` | Returns `DID`. |
| `awconfig.Account` | New `DID`, `Custody`, `Lifetime` fields. |
| `InboxMessage` / `ChatMessage` | New `VerificationStatus` field, populated on receive. |
| `Deregister(ctx) error` | New method. DELETE /v1/agents/me. |
| Automatic verification | aw verifies all incoming messages and populates `VerificationStatus`. |

### What bdh does

1. Pass `Custody="custodial"`, `Lifetime="ephemeral"` in Init().
2. Store returned `DID` in awconfig via `UpdateGlobal()`.
3. Read `VerificationStatus` on incoming messages, log non-verified.
4. Call `Deregister()` on worktree cleanup (graceful degradation if it fails).
5. Zero crypto code.

### What bdh does NOT do

- No keypair generation
- No signing
- No `NewWithIdentity()` constructor
- No TOFU pin management
- No identity mismatch handling

---

## 15. Implementation order

1. **`didkey.go`** — `ComputeDIDKey`, `ExtractPublicKey`. Unit tests against known test vectors.
2. **`signing.go`** — Canonical JSON, `SignMessage`, `VerifyMessage`, `VerificationStatus` type. Unit tests with round-trip sign/verify.
3. **`pinstore.go`** — TOFU pin storage. Unit tests for store/check/mismatch. Lifetime-aware: skip pins for ephemeral agents.
4. **`identity.go`** — `AgentIdentity` (with `Lifetime` field), `DIDKeyResolver`, `ChainResolver`. Unit tests.
5. **`awconfig/keys.go`** — Keypair generation, per-agent file naming, file storage. Unit tests.
6. **`awconfig/global_config.go`** — Add `DID`, `SigningKey`, `Custody`, `Lifetime` to `Account`. Tests for serialization roundtrip.
7. **`register.go` + `cmd/aw/register.go`** — Keypair generation at registration, send DID/public_key/custody/lifetime. Integration test.
8. **`init.go` + `cmd/aw/init.go`** — Same for init path. Store DID from response. Integration test.
9. **`deregister.go`** — `Deregister(ctx)` and `DeregisterAgent(ctx, namespace, alias)` client methods. Integration test.
10. **`client.go`** — Add `signingKey`/`did` to Client. `NewWithIdentity` constructor. `put` helper method.
11. **Message sending** — Sign outgoing messages in `SendMessage`, `NetworkSendMail`, `SendDM`, `ChatCreateSession`, `ChatSendMessage`. Integration tests.
12. **Message receiving** — Verify incoming signatures in `Inbox`, `ChatStream`, `ChatHistory`. Populate `VerificationStatus`. Integration tests.
13. **`cmd/aw/did.go`** — `aw did rotate-key`, `aw did rotate-key --self-custody`, `aw did log`. Rotation announcements. Integration tests.
14. **`cmd/aw/retire.go`** — `aw agent retire --successor`. Integration test.
15. **`cmd/aw/introspect.go`** — Add DID, custody, lifetime, public_key to output. Integration test.

Each step is a commit. Tests pass at every commit.
