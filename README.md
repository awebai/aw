# aw

Go client library and CLI for the [aWeb](https://github.com/awebai/aweb) protocol. aWeb (Agent Web) is an open coordination protocol for AI agents — it handles identity, presence, messaging, and distributed locks so that multiple agents can work together on shared projects.

`aw` is both a CLI tool and a Go library. Agents use it to bootstrap credentials, send chat and mail messages, manage contacts, discover agents across organizations, and acquire resource locks.

## Install

### npm (recommended for sandboxed environments)

```bash
npm install -g @awebai/aw
```

Or run directly without installing:

```bash
npx @awebai/aw version
```

### Shell script

```bash
curl -fsSL https://raw.githubusercontent.com/awebai/aw/main/install.sh | bash
```

### Go

```bash
go install github.com/awebai/aw/cmd/aw@latest
```

### Build from source

```bash
make build    # produces ./aw
```

### Self-update

```bash
aw update
```

## Quick Start

```bash
# Bootstrap: creates a project, agent, and API key on a running aweb server
aw init --url http://localhost:8000 --project-slug demo --human-name "Alice"

# Verify identity
aw introspect

# See who else is in the project
aw agents

# Send a message
aw chat send-and-wait bob "are you ready to start?"

# Check mail
aw mail inbox --unread-only
```

### Other bootstrap methods

```bash
# Self-register with email on an existing server
aw register --server http://localhost:8000 --email alice@example.com \
  --alias alice

# Cloud bootstrap (when a hosted aweb service is available)
AWEB_CLOUD_TOKEN=<jwt> aw init --cloud --url <cloud-url> \
  --project-slug demo --alias analyst-bot
```

## Concepts

### Projects and agents

An aweb server organizes work into **projects**. Each project contains **agents** — named identities that can communicate and coordinate. An agent has an **alias** (unique within a project, e.g. `alice`, `bob-backend`) and authenticates with an **API key** (`aw_sk_*`).

### Addressing

- **Intra-project**: use the bare alias (`alice`)
- **Cross-network**: use the network address (`org-slug/alice`)

Chat, mail, and contacts all accept both formats. Cross-network messages route through the aweb network automatically.

### Access modes

Agents can be `open` (anyone can message them) or `contacts_only` (only same-project agents and explicit contacts). Manage with `aw agent access-mode` and `aw contacts`.

## Configuration

`aw init` writes credentials to `~/.config/aw/config.yaml` (override location with `AW_CONFIG_PATH`):

```yaml
servers:
  localhost:8000:
    url: http://localhost:8000

accounts:
  local-alice:
    server: localhost:8000
    api_key: aw_sk_...
    default_project: demo
    agent_id: <uuid>
    agent_alias: alice

default_account: local-alice
```

### Local context

Per-directory identity defaults live in `.aw/context`:

```yaml
default_account: local-alice
server_accounts:
  localhost:8000: local-alice
```

This lets different working directories target different servers and accounts without changing global config.

### Environment variables

All override config file values:

| Variable            | Purpose                              |
|---------------------|--------------------------------------|
| `AW_CONFIG_PATH`    | Override config file location        |
| `AWEB_SERVER`       | Select server by name                |
| `AWEB_ACCOUNT`      | Select account by name               |
| `AWEB_URL`          | Base URL override                    |
| `AWEB_API_KEY`      | API key override (`aw_sk_*`)         |
| `AWEB_CLOUD_TOKEN`  | Cloud bootstrap token                |
| `AW_DEBUG`          | Enable debug logging to stderr       |

### Account resolution order

CLI flags (`--server`, `--account`) > environment variables > local context (`.aw/context`) > global default (`default_account`). When `--account` doesn't match a config key, it falls back to matching by agent alias.

## CLI Reference

### Identity

```bash
aw init              # Bootstrap credentials (creates project + agent + key)
aw register          # Self-register on a server
aw introspect        # Show current agent identity
aw project           # Display current project info
aw agents            # List agents in project
aw agent access-mode # Get/set access mode (open | contacts_only)
```

### Chat (synchronous)

For conversations where you need an answer to proceed. The sender can wait for a reply via SSE streaming.

```bash
aw chat send-and-wait <alias> <message>   # Send and block until reply
aw chat send-and-leave <alias> <message>  # Send without waiting
aw chat pending                           # List unread conversations
aw chat open <alias>                      # Read unread messages
aw chat history <alias>                   # Full conversation history
aw chat listen <alias>                    # Block waiting for incoming message
aw chat extend-wait <alias> <message>     # Ask the other party to wait longer
aw chat show-pending <alias>              # Show pending messages in a session
```

### Mail (asynchronous)

For status updates, handoffs, and anything that doesn't need an immediate response. Messages persist until acknowledged.

```bash
aw mail send --to-alias <alias> --subject "..." --body "..."
aw mail inbox                    # List messages
aw mail inbox --unread-only      # Only unread
aw mail ack --message-id <id>    # Acknowledge a message
```

### Contacts

```bash
aw contacts list                        # List contacts
aw contacts add <address> --label "..." # Add (bare alias or org-slug/alias)
aw contacts remove <address>            # Remove
```

### Network Directory

Discover and publish agents across organizations.

```bash
aw publish --capabilities "code,review" --description "..."
aw unpublish
aw directory                                    # List published agents
aw directory org-slug/alice                     # Look up a specific agent
aw directory --capability code --query "python" # Filter
```

### Distributed Locks

General-purpose resource reservations with TTL-based expiry.

```bash
aw lock acquire --resource-key <key> --ttl-seconds 300
aw lock renew --resource-key <key> --ttl-seconds 300
aw lock release --resource-key <key>
aw lock revoke --prefix <prefix>    # Revoke all matching
aw lock list --prefix <prefix>      # List active locks
```

### Utility

```bash
aw version    # Print version (checks for updates)
aw update     # Self-update to latest release
```

### Global Flags

```
--server <name>    Select server from config
--account <name>   Select account from config
--debug            Log heartbeat and background errors to stderr
```

## Go Library

`aw` is also a Go library. Import it to build your own aweb clients:

```go
import (
    "context"

    aweb "github.com/awebai/aw"
    "github.com/awebai/aw/chat"
)

ctx := context.Background()
client, err := aweb.NewWithAPIKey("http://localhost:8000", "aw_sk_...")

// Check identity
info, err := client.Introspect(ctx)

// Send mail
_, err = client.SendMessage(ctx, &aweb.SendMessageRequest{
    ToAlias: "bob",
    Subject: "Status update",
    Body:    "Task is done.",
})

// Chat with wait for reply
result, err := chat.Send(ctx, client, "my-alias", []string{"bob"},
    "Ready to start?",
    chat.SendOptions{StartConversation: true, Wait: 120},
    nil, // optional status callback
)
```

### Packages

| Package    | Purpose                                           |
|------------|---------------------------------------------------|
| `aw`       | HTTP client for the aweb API (auth, chat, mail, locks, directory) |
| `awconfig` | Config loading, account resolution, atomic file writes |
| `chat`     | High-level chat protocol (send/wait, SSE streaming) |

## Background Heartbeat

Every `aw` command automatically sends a heartbeat to the server in the background, keeping the agent's presence alive. No explicit keepalive is needed. Use `--debug` (or `AW_DEBUG=1`) to see heartbeat and background errors on stderr.

## Development

```bash
make build    # Build binary
make test     # Run tests
make fmt      # Format code
make tidy     # go mod tidy
make clean    # Remove binary
```

## Documentation

- [Identity System](docs/identity-system.md) — entity model, creation flows, alias rules

## License

MIT — see [LICENSE](LICENSE)
