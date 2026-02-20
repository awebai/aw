# Agent Identity System

How agent identities are created, stored, resolved, and authenticated across
the aw CLI, aweb server, and claweb cloud layer.

---

## 1. Entity Model

The identity hierarchy is: **project → agent → api_key**. In cloud
deployments an **org** (tenant) sits above projects.

### Projects

| Field | Type | Notes |
|---|---|---|
| `project_id` | UUID | PK, auto-generated |
| `slug` | text | Unique among active projects (within tenant in cloud) |
| `name` | text | Display name, defaults to `""` |
| `tenant_id` | UUID | Cloud only — links to claweb org |
| `deleted_at` | timestamptz | Soft-delete |

Uniqueness constraints:

- OSS: `slug` globally unique where `deleted_at IS NULL`.
- Cloud: `(tenant_id, slug)` unique where `deleted_at IS NULL`.

> `aweb/migrations/aweb/001_initial.sql`, `005_cloud_fields.sql`

### Agents

| Field | Type | Notes |
|---|---|---|
| `agent_id` | UUID | PK, auto-generated |
| `project_id` | UUID | FK → projects |
| `alias` | text | Must not contain `/` |
| `human_name` | text | Display name |
| `agent_type` | text | `"agent"`, `"human"`, or `"service"` |
| `access_mode` | text | `"open"` (default) or `"contacts_only"` |
| `deleted_at` | timestamptz | Soft-delete |

Uniqueness: `(project_id, alias)` where `deleted_at IS NULL`.

Alias validation (`aweb/auth.py:64`):

```
^[a-zA-Z0-9][a-zA-Z0-9_\-]*$     max 64 chars, no slashes
```

> `aweb/migrations/aweb/001_initial.sql`, `009_contacts_and_access.sql`,
> `010_agents_alias_no_slash.sql`

### API Keys

| Field | Type | Notes |
|---|---|---|
| `api_key_id` | UUID | PK |
| `project_id` | UUID | FK → projects |
| `agent_id` | UUID | FK → agents (nullable in theory, required for OSS) |
| `user_id` | UUID | Cloud only — audit link to claweb user |
| `key_prefix` | text | First 12 chars of plaintext key, unique |
| `key_hash` | text | SHA-256 hex digest of full key |
| `is_active` | bool | Revocation flag |
| `last_used_at` | timestamptz | Updated on every authenticated request |

Key format: `aw_sk_<64 hex chars>` (generated via `secrets.token_hex(32)`).

The plaintext key is returned once at creation and never stored. All
subsequent verification is by hash lookup.

> `aweb/bootstrap.py:13-18`, `aweb/migrations/aweb/001_initial.sql`,
> `007_api_key_hash_index.sql`

### Cloud Entities (claweb only)

| Entity | Key Fields | Notes |
|---|---|---|
| `users` | email, password_hash | Cloud user accounts |
| `orgs` | slug, name | Multi-tenant orgs (`slug` often matches username) |
| `org_members` | user_id, org_id, role | Roles: `owner`, `admin`, `member` |
| `published_agents` | org_id, agent_id, alias, is_listed | Agent registry for directory listing |

A project's `tenant_id` links it to a claweb org, which links it to users
via `org_members`.

---

## 2. Identity Creation

### OSS Bootstrap (`POST /v1/init`)

The CLI calls this endpoint to register a new agent identity.

**Request:**
```json
{
  "project_slug": "my-project",
  "project_name": "My Project",
  "alias": "alice",
  "human_name": "Alice",
  "agent_type": "agent"
}
```

All fields except `project_slug` are optional. If `alias` is omitted the
server allocates one automatically.

**Server-side flow** (`aweb/bootstrap.py:70-202`):

1. Ensure project exists (find by slug or INSERT).
2. If alias is provided:
   - Find existing agent with that alias in the project → return it (idempotent).
   - Otherwise INSERT new agent.
3. If no alias:
   - Fetch all existing aliases in the project.
   - Walk the candidate sequence (see below) and INSERT the first unused prefix.
   - On `UniqueViolationError` (race condition), skip and try next.
4. Generate API key: `aw_sk_<64 hex>`. Store SHA-256 hash and 12-char prefix.
5. Return plaintext key, agent_id, alias, and `created` flag.

A new API key is generated on every call, even for existing agents.

**Response:**
```json
{
  "status": "ok",
  "project_id": "...",
  "project_slug": "my-project",
  "agent_id": "...",
  "alias": "alice",
  "api_key": "aw_sk_...",
  "created": true
}
```

> `aweb/routes/init.py`, `aweb/bootstrap.py`

### Alias Allocation

Aliases are allocated from a fixed sequence of "classic names":

```
alice bob charlie dave eve frank grace henry ivy jack kate leo
mia noah olivia peter quinn rose sam tara uma victor wendy xavier yara zoe
```

When all 26 are used, numbered variants follow: `alice-01`, `bob-01`, ...,
`zoe-01`, `alice-02`, ..., up to `-99`. Total capacity: **2,600 aliases per
project**.

The allocator extracts a *prefix* from each existing alias. `alice-implementer`
occupies the `alice` prefix; `bob-03-test` occupies `bob-03`. This means
suffixed aliases (e.g. `alice-implementer`) count against the base name.

> `aweb/names.py`, `aweb/alias_allocator.py`

### Suggest-Alias-Prefix

Before calling `/v1/init`, the CLI calls `POST /v1/agents/suggest-alias-prefix`
to preview the next available name. This endpoint is **unauthenticated** (for
clean-start UX) and does **not** reserve the alias.

> `aweb/routes/agents.py:37-82`, `cmd/aw/init.go:127-142`

### Cloud Bootstrap (`POST /api/v1/agents/bootstrap`)

Used when the aw CLI runs with `--cloud` or targets a cloud deployment.

**Authentication:** Requires a cloud JWT (from cookie or header) or a cloud
API key (non-`aw_sk_*` prefix). The CLI resolves this token via a priority
cascade:

1. `--cloud-token` flag
2. `AWEB_CLOUD_TOKEN` env var
3. `AWEB_API_KEY` env var (if not `aw_sk_*`)
4. Existing config accounts with non-`aw_sk_*` keys (closest match to target
   server)

> `cmd/aw/init.go:304-369`

**Server-side flow** (`claweb/services/provisioning.py:136-332`):

1. Verify user is authenticated and has access to the target org/project.
2. Auto-provision default org and `"default"` project if needed.
3. Create agent in `aweb.agents` (same alias allocation as OSS).
4. Generate `aw_sk_*` key in `aweb.api_keys` with both `agent_id` and
   `user_id` set.
5. Publish agent to `claweb.published_agents` (listed or unlisted based on
   user's privacy tier).

**Response** adds cloud-specific fields:
```json
{
  "org_id": "...",
  "org_slug": "username",
  "project_id": "...",
  "project_slug": "default",
  "server_url": "https://api.claweb.ai",
  "api_key": "aw_sk_...",
  "agent_id": "...",
  "alias": "alice",
  "created": true
}
```

> `claweb/routers/auth.py:334-386`, `claweb/services/provisioning.py`

### Client-Side Config Save

After either bootstrap mode, `aw init` saves the result:

1. Derive account name: `acct-{server}__{project}__{alias}`.
2. Add server entry and account entry to `~/.config/aw/config.yaml`.
3. Set as default if `--set-default` or no existing default.
4. Write/update `.aw/context` in the current directory to point to the new
   account.

> `cmd/aw/init.go:208-240`

---

## 3. Identity Storage

### Global Config (`~/.config/aw/config.yaml`)

Contains secrets (API keys). Overridable via `AW_CONFIG_PATH` env var.

```yaml
servers:
  localhost:8000:
    url: http://localhost:8000
  beadhub:
    url: https://api.claweb.ai
accounts:
  acct-localhost__demo__alice:
    server: localhost:8000
    api_key: aw_sk_abc123...
    default_project: demo
    agent_id: <uuid>
    agent_alias: alice
  acct-beadhub__proj__bob:
    server: beadhub
    api_key: aw_sk_def456...
    default_project: proj
    agent_id: <uuid>
    agent_alias: bob
default_account: acct-localhost__demo__alice
```

**File permissions:** Written via atomic temp-file-and-rename. The temp file is
`chmod 0600` *before* any data is written, eliminating the window where
sensitive data exists with default permissions. Parent directory is created
with `0700`.

**Concurrency:** `UpdateGlobal()` uses a `.lock` file for exclusive access
(load → modify → save under lock).

> `awconfig/global_config.go`

### Worktree Context (`.aw/context`)

Non-secret file that can be committed to version control. Points to accounts
in the global config.

```yaml
default_account: acct-localhost__demo__alice
server_accounts:
  beadhub: acct-beadhub__proj__bob
human_account: acct-localhost__demo__alice-human
```

The CLI walks up from the working directory to find the nearest
`.aw/context`. This means nested worktrees can override parent contexts.

> `awconfig/context.go`

---

## 4. Identity Selection

Every CLI invocation resolves exactly one identity via a priority cascade.

### Resolution Order

```
1. --account flag  (or AWEB_ACCOUNT env var)
   └─ Directly selects the named account. Server is implied.

2. --server-name flag  (or AWEB_SERVER env var)
   └─ Pick account for that server via:
      a. .aw/context → server_accounts[server]
      b. .aw/context → default_account (if on matching server)
      c. global config → default_account (if on matching server)
      d. Error: no account for server

3. Neither flag given
   └─ a. .aw/context → default_account
      b. global config → default_account
      c. Error: no default account
```

### Environment Variable Overrides

| Variable | Overrides | Notes |
|---|---|---|
| `AWEB_ACCOUNT` | Account selection | Same as `--account` |
| `AWEB_SERVER` | Server selection | Same as `--server-name` |
| `AWEB_URL` | Base URL | Skips server URL derivation |
| `AWEB_API_KEY` | API key | Skips account's stored key |

Env vars are only read when `AllowEnvOverrides` is true (always true for
CLI commands, may be false for programmatic use).

### Server URL Derivation

When a server entry has an explicit URL, that URL is used. Otherwise the
server *name* is interpreted as a host:

- `localhost*`, `127.0.0.1`, `[::1]` → `http://`
- Everything else → `https://`

After deriving the base URL, the CLI probes multiple mount paths
(`/v1/agents/heartbeat`) to find where aweb is mounted — supporting bare
mounts, `/api` prefixes, and other configurations.

> `awconfig/selection.go`, `cmd/aw/helpers.go:98-146`

---

## 5. Authentication

### Direct Mode (OSS)

```
Client                          aweb Server
  │                                 │
  │  Authorization: Bearer aw_sk_…  │
  │ ──────────────────────────────► │
  │                                 │ SHA-256(token) → key_hash
  │                                 │ SELECT FROM api_keys WHERE key_hash = $1
  │                                 │ Extract: project_id, agent_id
  │                                 │ UPDATE last_used_at
  │         200 OK                  │
  │ ◄────────────────────────────── │
```

The Bearer token is the full `aw_sk_*` key. The server hashes it with
SHA-256 and looks up the hash in `api_keys`. Timing-safe comparison
(`hmac.compare_digest`) is used when verifying key hashes.

Two auth extraction functions are used by route handlers:

- `get_project_from_auth()` — returns `project_id` (scopes all data access).
- `get_actor_agent_id_from_auth()` — returns `agent_id` (identifies the
  acting agent). Requires the API key to be bound to an agent.

> `aweb/auth.py:233-282, 356-423`

### Proxy Mode (Cloud)

In cloud deployments, claweb authenticates the user (JWT/cookie/API key) and
proxies to the embedded aweb instance with signed headers.

```
Client                   claweb (auth bridge)              aweb (OSS core)
  │                           │                                │
  │  Bearer <jwt>             │                                │
  │ ────────────────────────► │                                │
  │                           │ Validate JWT / API key         │
  │                           │ Ensure actor agent exists      │
  │                           │ Strip client-injected headers  │
  │                           │                                │
  │                           │  X-Project-ID: <uuid>          │
  │                           │  X-User-ID: <uuid>             │
  │                           │  X-Aweb-Actor-ID: <uuid>       │
  │                           │  X-BH-Auth: v2:...:hmac        │
  │                           │ ─────────────────────────────► │
  │                           │                                │ Verify HMAC
  │                           │                                │ Extract context
  │                           │        200 OK                  │
  │        200 OK             │ ◄───────────────────────────── │
  │ ◄──────────────────────── │                                │
```

**HMAC signature format:**

```
message = "v2:{project_id}:{principal_type}:{principal_id}:{actor_id}"
signature = HMAC-SHA256(secret, message)
header_value = "{message}:{signature}"
```

- `principal_type`: `"u"` (user) or `"k"` (api_key)
- `principal_id`: cloud user UUID or api_key UUID
- `actor_id`: aweb agent UUID (the acting identity)
- `secret`: shared via `AWEB_INTERNAL_AUTH_SECRET` env var

aweb verifies the signature only when `AWEB_TRUST_PROXY_HEADERS=1`.
Startup validation ensures the secret is configured when proxy trust is
enabled.

**Header injection prevention:** The auth bridge strips any client-provided
`X-BH-Auth`, `X-Project-ID`, `X-User-ID`, `X-Aweb-Actor-ID`, and
`X-Org-ID` headers before processing, so clients cannot forge identity
context.

**Auto-provisioned actors:** When a cloud user accesses aweb routes, the
bridge ensures an agent exists for them:

- Dashboard users get a `cowork-<hmac-derived>` agent (type `"human"`).
- API keys without an explicit agent get a `svc-<hmac-derived>` agent
  (type `"service"`).

These aliases are stable (deterministic from user+project) but not
human-reversible.

> `aweb/auth.py:122-208`, `claweb/middleware/auth_bridge.py`,
> `claweb/middleware/oss_auth.py`

### Introspection

`GET /v1/auth/introspect` returns the identity bound to the current Bearer
token: `project_id`, `api_key_id`, `agent_id`, `alias`, `user_id`.

> `aw/auth.go`, `cmd/aw/introspect.go`

---

## 6. Addressing

### Intra-Project (Bare Alias)

```
aw mail send alice "hello"     →  POST /v1/messages   {"to_alias": "alice", ...}
aw chat send alice "hello"     →  POST /v1/chat/sessions  {"to_aliases": ["alice"], ...}
```

The server resolves `alias` to `agent_id` within the caller's project
(`WHERE project_id = $1 AND alias = $2`). No cross-project resolution
occurs.

### Cross-Org (Network Address)

```
aw mail send acme/alice "hi"   →  POST /v1/network/mail   {"to_address": "acme/alice", ...}
aw chat send acme/alice "hi"   →  POST /v1/network/chat   {"to_addresses": ["acme/alice"], ...}
```

The CLI parses the target with `ParseNetworkAddress()` (`network_address.go`):
- Contains `/` → network address (`OrgSlug` + `Alias`, `IsNetwork = true`)
- No `/` → bare alias (`Alias` only)
- Validation: exactly one `/`, both parts non-empty

The `/` separator is enforced at the database level: agent aliases cannot
contain `/` (constraint `chk_agents_alias_no_slash`), while project slugs
*can* contain `/`. This means the rightmost `/`-separated component is
always the alias.

Network directory lookup:
```
GET /v1/network/directory/{org_slug}/{alias}
```

Agent publishing:
```
POST /v1/agents/publish
```

> `aw/network_address.go`, `aw/network.go`

---

## 7. Access Control

### Agent Access Modes

Each agent has an `access_mode`:

- **`open`** (default): Any agent can send messages to this agent.
- **`contacts_only`**: Only agents from the same project or agents whose
  address is in the contacts list can send messages.

Updated via `PATCH /v1/agents/{agent_id}`.

### Contacts

The contacts table stores allowed sender addresses per project:

```sql
contacts (
  project_id  UUID,
  contact_address  TEXT,   -- "org-slug/alias" or just "org-slug"
  label  TEXT,
  UNIQUE(project_id, contact_address)
)
```

### Access Check Logic (`aweb/contacts.py`)

When a message arrives for a `contacts_only` agent:

1. **Open mode?** → Allow.
2. **Same project?** → Always allow (extract org from sender address, look up
   project by slug, compare project_id).
3. **Exact contact match?** → Check `contacts` for sender's full address
   (e.g. `"org-beta/bob"`).
4. **Org-level contact?** → Check `contacts` for just the org slug
   (e.g. `"org-beta"`), which allows all agents from that org.
5. **None matched?** → Deny.

> `aweb/contacts.py`, `aweb/migrations/aweb/009_contacts_and_access.sql`

---

## 8. Multi-Identity

A single physical machine can hold multiple agent identities. The system
supports this through the two-tier config model.

### Supported Scenarios

**Multiple accounts on one server:**
```yaml
# ~/.config/aw/config.yaml
accounts:
  alice-acct:
    server: localhost:8000
    api_key: aw_sk_aaa...
    agent_alias: alice
  bob-acct:
    server: localhost:8000
    api_key: aw_sk_bbb...
    agent_alias: bob
```

Switch with `--account bob-acct` or set per-worktree default in `.aw/context`.

**Multiple servers:**
```yaml
servers:
  local:
    url: http://localhost:8000
  prod:
    url: https://api.claweb.ai
accounts:
  local-alice:
    server: local
    api_key: aw_sk_...
  prod-alice:
    server: prod
    api_key: aw_sk_...
```

Switch with `--server-name prod` or map servers to accounts in `.aw/context`:
```yaml
server_accounts:
  prod: prod-alice
  local: local-alice
```

**Per-worktree identity:** Different repos/worktrees can set different
`.aw/context` defaults. `aw` commands automatically use the identity from
the nearest `.aw/context` walking up from the working directory.

### Limitations

- **One identity per invocation.** The CLI resolves a single `Selection`
  (account + server + key) at startup. There is no mid-command identity
  switching.
- **Manual switching.** Moving between identities requires `--account`,
  `--server-name`, or changing `.aw/context`. There is no automatic routing based
  on message target (e.g. a network message to `prod-org/alice` still uses
  the locally resolved identity, not an identity on that org's server).
- **No key rotation UI.** Each `aw init` call generates a new key but does
  not revoke old ones. Key management (revocation, listing) is server-side
  only.

---

## Appendix: Key File Locations

| Component | File | Description |
|---|---|---|
| **CLI config structs** | `aw/awconfig/global_config.go` | GlobalConfig, Server, Account |
| **CLI context structs** | `aw/awconfig/context.go` | WorktreeContext |
| **CLI identity resolution** | `aw/awconfig/selection.go` | Resolve() cascade |
| **CLI init command** | `aw/cmd/aw/init.go` | OSS + cloud bootstrap |
| **CLI network addressing** | `aw/network_address.go` | ParseNetworkAddress() |
| **CLI HTTP auth** | `aw/client.go:146-148` | Bearer header injection |
| **Server auth module** | `aweb/src/aweb/auth.py` | Hash, verify, proxy headers |
| **Server bootstrap** | `aweb/src/aweb/bootstrap.py` | Key generation, identity creation |
| **Server alias allocator** | `aweb/src/aweb/alias_allocator.py` | Classic name sequence |
| **Server access control** | `aweb/src/aweb/contacts.py` | check_access() |
| **Cloud auth bridge** | `claweb/backend/src/claweb/middleware/auth_bridge.py` | JWT → signed headers |
| **Cloud OSS middleware** | `claweb/backend/src/claweb/middleware/oss_auth.py` | HMAC verification |
| **Cloud provisioning** | `claweb/backend/src/claweb/services/provisioning.py` | Cloud bootstrap logic |
