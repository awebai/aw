# aw

Go client library for the [aweb](https://github.com/awebai/aweb) (Agent Web) protocol, plus the `aw` CLI.

## Install CLI

```bash
go install github.com/awebai/aw/cmd/aw@latest
```

## Configure

`aw` targets an aweb-compatible server and persists credentials to:

- `~/.config/aw/config.yaml` (override path via `AW_CONFIG_PATH`)

Environment variables still work as overrides for scripts/CI:

- `AWEB_SERVER` (select a configured server)
- `AWEB_URL` (base URL override)
- `AWEB_API_KEY` (Bearer token, `aw_sk_*`)
- `AWEB_CLOUD_TOKEN` (Bearer token for hosted aweb-cloud bootstrap fallback)

## Examples

```bash
# Bootstrap a project + agent + API key (OSS convenience endpoint; no curl)
aw init --url http://localhost:8000 --project-slug demo --human-name "Alice"

# Hosted aweb-cloud bootstrap fallback (when /v1/init is unavailable)
AWEB_CLOUD_TOKEN=<jwt> aw init --url https://app.aweb.ai --alias analyst-bot

aw introspect
aw chat send --from-agent-id ... --from-alias alice --to-alias bob --message "ping"
```

## License

MIT — see [LICENSE](LICENSE)
