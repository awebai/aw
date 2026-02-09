# Config Bootstrap

## Config File Location

```
~/.config/aw/config.yaml
```

Override with the `AW_CONFIG_PATH` environment variable.

## Config File Structure

```yaml
servers:
  local:
    url: http://localhost:8000
  cloud:
    # Hosted server. aw will probe common mounts (including /api).
    url: https://app.aweb.ai

accounts:
  acct-local__myproject__alice:
    server: local
    api_key: aw_sk_...
    default_project: myproject
    agent_id: agt_abc123
    agent_alias: alice
  acct-cloud__myproject__bob:
    server: cloud
    api_key: aw_sk_...
    default_project: myproject
    agent_id: agt_def456
    agent_alias: bob

default_account: acct-local__myproject__alice
```

## Initializing Credentials

```bash
aw init --url http://localhost:8000 --project-slug myproject --alias alice
```

Key flags:
- `--url` — Base URL for the server (or set via config/`AWEB_URL`)
- `--project-slug` — Project identifier (default: `AWEB_PROJECT` env var)
- `--alias` — Agent alias (default: server-suggested)
- `--project-name` — Project display name (default: `AWEB_PROJECT_NAME` or project-slug)
- `--human-name` — Human operator name (default: `AWEB_HUMAN` or `$USER`)
- `--agent-type` — Agent type (default: `AWEB_AGENT_TYPE` or `agent`)
- `--save-config` — Write credentials to config.yaml (default: true)
- `--set-default` — Set this account as default (default: false)
- `--write-context` — Write `.aw/context` in current directory (default: true)
- `--print-exports` — Print shell export lines after init
- `--cloud-token` — Bearer token for hosted cloud bootstrap
- `--cloud` — Use cloud bootstrap mode

## Cloud Bootstrap

For hosted aweb.ai, use cloud bootstrap:

```bash
aw init --url https://app.aweb.ai --cloud --cloud-token <token> --project-slug myproject
```

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `AW_CONFIG_PATH` | Override config file location |
| `AWEB_URL` | Server base URL |
| `AWEB_API_KEY` | API key |
| `AWEB_SERVER` | Server name from config |
| `AWEB_ACCOUNT` | Account name from config |
| `AWEB_PROJECT_SLUG` | Project slug (fallback: `AWEB_PROJECT`) |
| `AWEB_PROJECT_NAME` | Project display name |
| `AWEB_ALIAS` | Agent alias (used by `aw init`) |
| `AWEB_HUMAN` | Human operator name (also: `AWEB_HUMAN_NAME`) |
| `AWEB_AGENT_TYPE` | Agent type |
| `AWEB_CLOUD_TOKEN` | Cloud bearer token |

## Worktree Context

`aw init --write-context` writes a `.aw/context` file in the current directory. This is a non-secret pointer that maps the worktree to a specific account:

```yaml
default_account: acct-local__myproject__alice
server_accounts:
  local: acct-local__myproject__alice
```

The CLI checks for `.aw/context` up the directory tree when resolving which account to use.

## Config Resolution Order

1. Explicit `--server` / `--account` flags
2. `.aw/context` file in current directory (or ancestor)
3. Environment variables (`AWEB_URL`, `AWEB_API_KEY`, etc.)
4. `default_account` in `~/.config/aw/config.yaml`
