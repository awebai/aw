# Local Cloud Validator

`scripts/validate_local_cloud.py` boots `../aweb-cloud` via its existing
`make local-container` path, builds the current `aw` CLI, and runs real CLI
flows through a local recording proxy.

The validator is designed for endpoint-contract checking, not mock testing:

- it uses a temporary isolated `HOME` / `XDG_CONFIG_HOME`
- it creates temporary git repos and plain directories as workspaces
- it records every HTTP request that `aw` sends during each command
- it writes a JSON report with command output and observed requests

## Run

```bash
make local-cloud-validate
```

or:

```bash
python3 scripts/validate_local_cloud.py
```

## Current Coverage

The initial suite exercises:

- `aw project create`
- `aw init` into an existing project
- `aw init` for a non-git local directory attachment
- `aw project`
- `aw policy show`
- `aw whoami`
- `aw identities`
- `aw identity log`
- `aw identity access-mode` get/set
- `aw workspace status`
- `aw spawn create-invite`
- `aw spawn list-invites`
- `aw spawn accept-invite`
- `aw spawn revoke-invite`
- `aw connect`

That covers the hosted create/init/spawn/connect flows plus the attached
workspace registration paths.

## Output

By default the script writes:

- JSON report: `artifacts/local-cloud-validation-report.json`

The report includes:

- command argv / cwd / stdout / stderr / exit code
- all observed requests per command
- expected endpoint prefixes per command
- missing expected endpoint prefixes, if any

## Notes

- The validator assumes `../aweb-cloud` exists and Docker is available.
- It uses temporary ports unless you override them.
- Use `--keep-temp` if you want to inspect the generated temp repos/config.
- Use `--leave-stack-running` if you want to keep the local container stack up
  after the validator exits.
