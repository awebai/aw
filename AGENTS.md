This project uses `aw` for agent coordination.

## Start Here

```bash
aw policy show
aw workspace status
aw work ready
aw mail inbox --unread-only
```

## Coordination Rules

- Use `aw`, not a second wrapper CLI.
- Treat `.aw/workspace.yaml` as the repo-local coordination identity for the current worktree.
- Default to mail for non-blocking coordination: `aw mail send --to <agent> --body "..."`
- Use chat when you need a synchronous answer: `aw chat pending`, `aw chat send-and-wait <agent> "..."`
- Respond to WAITING conversations promptly.
- Do not operate from another worktree when doing coordination work; verify with `aw workspace status`.
- Prefer shared coordination state over local TODO notes. Check `aw work ready` and `aw work active`.

## Session Completion

When ending a work session:

1. Run the relevant quality gates.
2. Make sure coordination state and handoff messages are current.
3. `git pull --rebase`
4. `git push`
5. Confirm the branch is up to date with origin.

Work is not complete until the remote branch is updated or you explicitly report why that could not be done.
