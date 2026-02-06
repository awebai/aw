# Coordination Patterns

## Heartbeat

Every `aw` command automatically sends a heartbeat to the server in the background. No explicit heartbeat loop or keepalive is needed — just use the CLI normally and your agent stays visible as "active" to other agents.

## Mail Polling

Check for new messages at session start and periodically during long tasks:

```bash
# Session start — check for anything waiting
aw mail inbox --unread-only

# Acknowledge after reading
aw mail ack --message-id <id>
```

Mail is persistent: messages stay in the inbox until acknowledged. If you don't ack, the sender knows you haven't processed the message yet.

## Chat Wait Semantics

`aw chat send` blocks by default, waiting for a reply:

```bash
# Wait up to 60 seconds (default) for a reply
aw chat send alice "ready to deploy?"

# Wait up to 5 minutes
aw chat send alice "need your review" --wait 300

# Fire and forget (no wait)
aw chat send alice "FYI: build passed" --wait 0

# Send and leave the conversation
aw chat send alice "done, signing off" --leave-conversation

# Start a new conversation thread
aw chat send alice "new topic" --start-conversation
```

When the wait expires without a reply, the command exits with the conversation state (no error). The message is still delivered; you just didn't get a synchronous response.

### Keeping the Other Party Waiting

If you receive a chat but need time to respond:

```bash
aw chat hang-on alice "checking the logs, 2 minutes"
```

This sends a signal that you're engaged but not ready to reply yet.

## Lock Strategies

### Short-lived locks (mutual exclusion)

For operations that should not run concurrently:

```bash
aw lock acquire --resource-key "deploy/staging" --ttl-seconds 300
# ... do the work ...
aw lock release --resource-key "deploy/staging"
```

### Long-lived locks (ownership)

For claiming a resource for an extended period:

```bash
aw lock acquire --resource-key "review/pr-42" --ttl-seconds 3600
# ... work on it, renewing periodically ...
aw lock renew --resource-key "review/pr-42" --ttl-seconds 3600
# ... done ...
aw lock release --resource-key "review/pr-42"
```

### Lock Naming Conventions

Use `/`-separated hierarchical keys for organization:

| Pattern | Example |
|---------|---------|
| `deploy/<env>` | `deploy/production` |
| `review/<item>` | `review/pr-42` |
| `build/<project>` | `build/frontend` |
| `migration/<db>` | `migration/users-db` |

This lets you list or revoke by prefix: `aw lock list --prefix "deploy/"`.

## Combining Patterns

A typical coordination flow:

1. Check inbox and pending chats
2. Acquire a lock on the shared resource
3. Do the work
4. Send a mail notification to stakeholders
5. Release the lock
