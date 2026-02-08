// ABOUTME: Chat protocol functions composing low-level aweb-go client methods.
// ABOUTME: Provides Send, Open, History, Pending, HangOn, and ShowPending.

package chat

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
)

const DefaultWait = 120 // Default wait timeout in seconds for replies

// maxStreamDeadline is the server-side SSE connection safety net.
// The local waitTimer manages actual wait semantics; this just prevents
// orphaned server connections. Must exceed any possible wait extension chain.
const maxStreamDeadline = 15 * time.Minute

// MaxSendTimeout is the maximum duration a Send() call can take,
// accounting for all possible wait extensions.
const MaxSendTimeout = 16 * time.Minute

// sseResult wraps an SSE event or error for channel-based processing.
type sseResult struct {
	event *aweb.SSEEvent
	err   error
}

// streamToChannel bridges SSEStream.Next() to a channel for select-based processing.
// Returns the event channel and a cleanup function. The cleanup function closes the
// stream, signals the goroutine to stop, and blocks until it has exited.
// The caller must call cleanup to avoid goroutine leaks.
func streamToChannel(ctx context.Context, stream *aweb.SSEStream) (<-chan sseResult, func()) {
	ch := make(chan sseResult, 10)
	stopCtx, stopCancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(ch)
		defer close(done)
		for {
			ev, err := stream.Next()
			if err != nil {
				select {
				case ch <- sseResult{err: err}:
				case <-stopCtx.Done():
				}
				return
			}
			select {
			case ch <- sseResult{event: ev}:
			case <-stopCtx.Done():
				return
			}
		}
	}()
	cleanup := func() {
		stopCancel()
		stream.Close()
		<-done
	}
	return ch, cleanup
}

// parseSSEEvent converts an SSE event to a chat Event.
func parseSSEEvent(sseEvent *aweb.SSEEvent) Event {
	ev := Event{
		Type: sseEvent.Event,
	}

	var data map[string]any
	if err := json.Unmarshal([]byte(sseEvent.Data), &data); err != nil {
		return ev
	}

	if v, ok := data["agent"].(string); ok {
		ev.Agent = v
	}
	if v, ok := data["session_id"].(string); ok {
		ev.SessionID = v
	}
	if v, ok := data["message_id"].(string); ok {
		ev.MessageID = v
	}
	if v, ok := data["from_agent"].(string); ok {
		ev.FromAgent = v
	} else if v, ok := data["from"].(string); ok {
		ev.FromAgent = v
	}
	if v, ok := data["body"].(string); ok {
		ev.Body = v
	}
	if v, ok := data["by"].(string); ok {
		ev.By = v
	}
	if v, ok := data["reason"].(string); ok {
		ev.Reason = v
	}
	if v, ok := data["timestamp"].(string); ok {
		ev.Timestamp = v
	}
	if v, ok := data["sender_leaving"].(bool); ok {
		ev.SenderLeaving = v
	}
	if v, ok := data["sender_waiting"].(bool); ok {
		ev.SenderWaiting = v
	}
	if v, ok := data["reader_alias"].(string); ok {
		ev.ReaderAlias = v
	}
	if v, ok := data["hang_on"].(bool); ok {
		ev.HangOn = v
	}
	if v, ok := data["extends_wait_seconds"].(float64); ok {
		ev.ExtendsWaitSeconds = int(v)
	}

	return ev
}

// findSession finds the session ID for a conversation with targetAlias.
// Checks pending first (captures sender_waiting), falls back to listing sessions.
func findSession(ctx context.Context, client *aweb.Client, targetAlias string) (sessionID string, senderWaiting bool, err error) {
	pendingResp, err := client.ChatPending(ctx)
	if err != nil {
		return "", false, fmt.Errorf("getting pending chats: %w", err)
	}

	var bestPendingID string
	var bestPendingWaiting bool
	bestPendingSize := 0
	for _, p := range pendingResp.Pending {
		for _, participant := range p.Participants {
			if participant == targetAlias {
				if bestPendingSize == 0 || len(p.Participants) < bestPendingSize {
					bestPendingID = p.SessionID
					bestPendingWaiting = p.SenderWaiting
					bestPendingSize = len(p.Participants)
				}
				break
			}
		}
	}
	if bestPendingID != "" {
		return bestPendingID, bestPendingWaiting, nil
	}

	// Fallback to listing all sessions.
	sessionsResp, err := client.ChatListSessions(ctx)
	if err != nil {
		return "", false, fmt.Errorf("listing chat sessions: %w", err)
	}
	var bestSessionID string
	bestSessionSize := 0
	for _, s := range sessionsResp.Sessions {
		for _, participant := range s.Participants {
			if participant == targetAlias {
				if bestSessionSize == 0 || len(s.Participants) < bestSessionSize {
					bestSessionID = s.SessionID
					bestSessionSize = len(s.Participants)
				}
				break
			}
		}
	}
	if bestSessionID != "" {
		return bestSessionID, false, nil
	}

	return "", false, fmt.Errorf("no conversation found with %s", targetAlias)
}

// streamOpener opens an SSE stream for a chat session.
type streamOpener func(ctx context.Context, sessionID string, deadline time.Time) (*aweb.SSEStream, error)

// sendResponse normalizes the response from ChatCreateSession or NetworkCreateChat.
type sendResponse struct {
	SessionID        string
	MessageID        string
	TargetsConnected []string
	TargetsLeft      []string
}

// Send sends a message to target agents and optionally waits for a reply.
//
// Wait logic:
//   - opts.Leaving: send with leaving=true, exit immediately
//   - opts.Wait == 0: send, return immediately
//   - opts.StartConversation: ignore targets_left, use 5min wait unless WaitExplicit
//   - default: send, if all targets in targets_left → skip wait; else wait opts.Wait seconds
func Send(ctx context.Context, client *aweb.Client, myAlias string, targets []string, message string, opts SendOptions, callback StatusCallback) (*SendResult, error) {
	createResp, err := client.ChatCreateSession(ctx, &aweb.ChatCreateSessionRequest{
		ToAliases: targets,
		Message:   message,
		Leaving:   opts.Leaving,
	})
	if err != nil {
		return nil, fmt.Errorf("sending message: %w", err)
	}

	return sendCommon(ctx, client.ChatStream, sendResponse{
		SessionID:        createResp.SessionID,
		MessageID:        createResp.MessageID,
		TargetsConnected: createResp.TargetsConnected,
		TargetsLeft:      createResp.TargetsLeft,
	}, myAlias, targets, message, opts, callback)
}

// SendNetwork sends a message via the network (cross-org) endpoint and optionally waits for a reply.
// Uses the same wait semantics as Send but routes through /api/v1/network/chat.
func SendNetwork(ctx context.Context, client *aweb.Client, myAlias string, targets []string, message string, opts SendOptions, callback StatusCallback) (*SendResult, error) {
	createResp, err := client.NetworkCreateChat(ctx, &aweb.NetworkChatCreateRequest{
		ToAddresses: targets,
		Message:     message,
		Leaving:     opts.Leaving,
	})
	if err != nil {
		return nil, fmt.Errorf("sending network message: %w", err)
	}

	return sendCommon(ctx, client.NetworkChatStream, sendResponse{
		SessionID:        createResp.SessionID,
		MessageID:        createResp.MessageID,
		TargetsConnected: createResp.TargetsConnected,
		TargetsLeft:      createResp.TargetsLeft,
	}, myAlias, targets, message, opts, callback)
}

// sendCommon handles the post-send wait logic shared by Send and SendNetwork.
func sendCommon(ctx context.Context, openStream streamOpener, resp sendResponse, myAlias string, targets []string, message string, opts SendOptions, callback StatusCallback) (*SendResult, error) {
	result := &SendResult{
		SessionID:   resp.SessionID,
		Status:      "sent",
		TargetAgent: strings.Join(targets, ", "),
		Events:      []Event{},
	}

	if opts.Leaving {
		return result, nil
	}

	if opts.Wait == 0 {
		return result, nil
	}

	// Check if any target has left
	targetHasLeft := false
	for _, leftAlias := range resp.TargetsLeft {
		for _, target := range targets {
			if leftAlias == target {
				targetHasLeft = true
				break
			}
		}
		if targetHasLeft {
			break
		}
	}

	if targetHasLeft && !opts.StartConversation {
		result.Status = "targets_left"
		return result, nil
	}

	// Check target connection status (informational)
	allTargetsConnected := true
	for _, target := range targets {
		found := false
		for _, alias := range resp.TargetsConnected {
			if alias == target {
				found = true
				break
			}
		}
		if !found {
			allTargetsConnected = false
			break
		}
	}
	if !allTargetsConnected {
		result.TargetNotConnected = true
	}

	// Determine wait timeout
	waitSeconds := opts.Wait
	if opts.StartConversation && !opts.WaitExplicit {
		waitSeconds = 300 // 5 minutes
	}
	waitTimeout := time.Duration(waitSeconds) * time.Second

	// SSE stream for reply waiting. The server deadline is a safety net for
	// orphaned connections — the local waitTimer manages actual wait semantics.
	waitDeadline := time.Now().Add(waitTimeout)
	stream, err := openStream(ctx, resp.SessionID, time.Now().Add(maxStreamDeadline))
	if err != nil {
		return nil, fmt.Errorf("connecting to SSE: %w", err)
	}
	events, streamCleanup := streamToChannel(ctx, stream)
	defer streamCleanup()

	// Skip replayed messages — wait until we see our own sent message.
	sentMessageID := resp.MessageID
	seenSentMessage := sentMessageID == ""

	waitStart := time.Now()
	waitTimer := time.NewTimer(waitTimeout)
	defer func() {
		if !waitTimer.Stop() {
			select {
			case <-waitTimer.C:
			default:
			}
		}
	}()

	extendWait := func(extendsSeconds int, reason string) {
		if extendsSeconds <= 0 {
			return
		}
		if time.Now().After(waitDeadline) {
			waitDeadline = time.Now()
		}
		waitDeadline = waitDeadline.Add(time.Duration(extendsSeconds) * time.Second)

		if !waitTimer.Stop() {
			select {
			case <-waitTimer.C:
			default:
			}
		}
		waitTimer.Reset(time.Until(waitDeadline))

		if callback != nil {
			minutes := extendsSeconds / 60
			if minutes > 0 {
				callback("wait_extended", fmt.Sprintf("wait extended by %d min (%s)", minutes, reason))
			} else {
				callback("wait_extended", fmt.Sprintf("wait extended by %ds (%s)", extendsSeconds, reason))
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-waitTimer.C:
			result.WaitedSeconds = int(time.Since(waitStart).Seconds())
			return result, nil
		case sr, ok := <-events:
			if !ok || sr.err != nil {
				result.WaitedSeconds = int(time.Since(waitStart).Seconds())
				return result, nil
			}

			chatEvent := parseSSEEvent(sr.event)
			result.Events = append(result.Events, chatEvent)

			if chatEvent.Type == "read_receipt" {
				if callback != nil {
					callback("read_receipt", fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				if chatEvent.ExtendsWaitSeconds > 0 {
					extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				continue
			}

			if chatEvent.Type == "message" {
				if !seenSentMessage {
					if chatEvent.MessageID != "" && chatEvent.MessageID == sentMessageID {
						seenSentMessage = true
						continue
					}
					if chatEvent.MessageID == "" && chatEvent.FromAgent == myAlias && chatEvent.Body == message {
						seenSentMessage = true
						continue
					}
					continue
				}

				isFromTarget := false
				for _, target := range targets {
					if chatEvent.FromAgent == target {
						isFromTarget = true
						break
					}
				}
				if isFromTarget {
					if chatEvent.HangOn {
						if callback != nil {
							callback("hang_on", fmt.Sprintf("%s: %s", chatEvent.FromAgent, chatEvent.Body))
						}
						if chatEvent.ExtendsWaitSeconds > 0 {
							extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s requested more time", chatEvent.FromAgent))
						} else if callback != nil {
							callback("hang_on", fmt.Sprintf("%s requested more time", chatEvent.FromAgent))
						}
						continue
					}

					result.SenderWaiting = chatEvent.SenderWaiting

					if chatEvent.SenderLeaving {
						result.Status = "sender_left"
						result.Reply = chatEvent.Body
						return result, nil
					}

					result.Status = "replied"
					result.Reply = chatEvent.Body
					return result, nil
				}
			}
		}
	}
}

// Listen waits for a message in an existing conversation without sending.
// Returns on any message in the session (not filtered by sender).
// Returns *SendResult for compatibility with existing formatting code.
func Listen(ctx context.Context, client *aweb.Client, targetAlias string, waitSeconds int, callback StatusCallback) (*SendResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	result := &SendResult{
		SessionID:   sessionID,
		Status:      "sent",
		TargetAgent: targetAlias,
		Events:      []Event{},
	}

	waitTimeout := time.Duration(waitSeconds) * time.Second
	waitDeadline := time.Now().Add(waitTimeout)

	stream, err := client.ChatStream(ctx, sessionID, time.Now().Add(maxStreamDeadline))
	if err != nil {
		return nil, fmt.Errorf("connecting to SSE: %w", err)
	}
	events, streamCleanup := streamToChannel(ctx, stream)
	defer streamCleanup()

	waitStart := time.Now()
	waitTimer := time.NewTimer(waitTimeout)
	defer func() {
		if !waitTimer.Stop() {
			select {
			case <-waitTimer.C:
			default:
			}
		}
	}()

	extendWait := func(extendsSeconds int, reason string) {
		if extendsSeconds <= 0 {
			return
		}
		if time.Now().After(waitDeadline) {
			waitDeadline = time.Now()
		}
		waitDeadline = waitDeadline.Add(time.Duration(extendsSeconds) * time.Second)

		if !waitTimer.Stop() {
			select {
			case <-waitTimer.C:
			default:
			}
		}
		waitTimer.Reset(time.Until(waitDeadline))

		if callback != nil {
			minutes := extendsSeconds / 60
			if minutes > 0 {
				callback("wait_extended", fmt.Sprintf("wait extended by %d min (%s)", minutes, reason))
			} else {
				callback("wait_extended", fmt.Sprintf("wait extended by %ds (%s)", extendsSeconds, reason))
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-waitTimer.C:
			result.WaitedSeconds = int(time.Since(waitStart).Seconds())
			return result, nil
		case sr, ok := <-events:
			if !ok || sr.err != nil {
				result.WaitedSeconds = int(time.Since(waitStart).Seconds())
				return result, nil
			}

			chatEvent := parseSSEEvent(sr.event)
			result.Events = append(result.Events, chatEvent)

			if chatEvent.Type == "read_receipt" {
				if callback != nil {
					callback("read_receipt", fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				if chatEvent.ExtendsWaitSeconds > 0 {
					extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s opened the conversation", chatEvent.ReaderAlias))
				}
				continue
			}

			if chatEvent.Type == "message" {
				if chatEvent.HangOn {
					if callback != nil {
						callback("hang_on", fmt.Sprintf("%s: %s", chatEvent.FromAgent, chatEvent.Body))
					}
					if chatEvent.ExtendsWaitSeconds > 0 {
						extendWait(chatEvent.ExtendsWaitSeconds, fmt.Sprintf("%s requested more time", chatEvent.FromAgent))
					} else if callback != nil {
						callback("hang_on", fmt.Sprintf("%s requested more time", chatEvent.FromAgent))
					}
					continue
				}

				if chatEvent.SenderLeaving {
					result.Status = "sender_left"
					result.Reply = chatEvent.Body
					return result, nil
				}

				result.Status = "replied"
				result.Reply = chatEvent.Body
				return result, nil
			}
		}
	}
}

// Open fetches unread messages for a conversation and marks them as read.
func Open(ctx context.Context, client *aweb.Client, targetAlias string) (*OpenResult, error) {
	sessionID, senderWaiting, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	messagesResp, err := client.ChatHistory(ctx, aweb.ChatHistoryParams{
		SessionID:  sessionID,
		UnreadOnly: true,
		Limit:      1000,
	})
	if err != nil {
		return nil, fmt.Errorf("getting unread messages: %w", err)
	}

	result := &OpenResult{
		SessionID:     sessionID,
		TargetAgent:   targetAlias,
		Messages:      make([]Event, len(messagesResp.Messages)),
		MarkedRead:    0,
		SenderWaiting: senderWaiting,
	}

	if len(messagesResp.Messages) == 0 {
		result.UnreadWasEmpty = true
		return result, nil
	}

	for i, m := range messagesResp.Messages {
		result.Messages[i] = Event{
			Type:          "message",
			MessageID:     m.MessageID,
			FromAgent:     m.FromAgent,
			Body:          m.Body,
			Timestamp:     m.Timestamp,
			SenderLeaving: m.SenderLeaving,
		}
	}

	lastMessageID := messagesResp.Messages[len(messagesResp.Messages)-1].MessageID
	_, err = client.ChatMarkRead(ctx, sessionID, &aweb.ChatMarkReadRequest{
		UpToMessageID: lastMessageID,
	})
	if err != nil {
		return nil, fmt.Errorf("marking messages as read: %w", err)
	}
	result.MarkedRead = len(messagesResp.Messages)

	return result, nil
}

// History fetches all messages in a conversation.
func History(ctx context.Context, client *aweb.Client, targetAlias string) (*HistoryResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	messagesResp, err := client.ChatHistory(ctx, aweb.ChatHistoryParams{
		SessionID: sessionID,
		Limit:     1000,
	})
	if err != nil {
		return nil, fmt.Errorf("getting messages: %w", err)
	}

	result := &HistoryResult{
		SessionID: sessionID,
		Messages:  make([]Event, len(messagesResp.Messages)),
	}
	for i, m := range messagesResp.Messages {
		result.Messages[i] = Event{
			Type:      "message",
			FromAgent: m.FromAgent,
			Body:      m.Body,
			Timestamp: m.Timestamp,
		}
	}

	return result, nil
}

// Pending lists conversations with unread messages.
func Pending(ctx context.Context, client *aweb.Client) (*PendingResult, error) {
	resp, err := client.ChatPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting pending chats: %w", err)
	}

	result := &PendingResult{
		Pending:         make([]PendingConversation, len(resp.Pending)),
		MessagesWaiting: resp.MessagesWaiting,
	}
	for i, p := range resp.Pending {
		result.Pending[i] = PendingConversation{
			SessionID:            p.SessionID,
			Participants:         p.Participants,
			LastMessage:          p.LastMessage,
			LastFrom:             p.LastFrom,
			UnreadCount:          p.UnreadCount,
			LastActivity:         p.LastActivity,
			SenderWaiting:        p.SenderWaiting,
			TimeRemainingSeconds: p.TimeRemainingSeconds,
		}
	}

	return result, nil
}

// HangOn sends a hang-on message requesting more time to reply.
func HangOn(ctx context.Context, client *aweb.Client, targetAlias string, message string) (*HangOnResult, error) {
	sessionID, _, err := findSession(ctx, client, targetAlias)
	if err != nil {
		return nil, err
	}

	msgResp, err := client.ChatSendMessage(ctx, sessionID, &aweb.ChatSendMessageRequest{
		Body:   message,
		HangOn: true,
	})
	if err != nil {
		return nil, fmt.Errorf("sending hang-on message: %w", err)
	}

	return &HangOnResult{
		SessionID:          sessionID,
		TargetAgent:        targetAlias,
		Message:            message,
		ExtendsWaitSeconds: msgResp.ExtendsWaitSeconds,
	}, nil
}

// ShowPending shows the pending conversation with a specific agent.
func ShowPending(ctx context.Context, client *aweb.Client, targetAlias string) (*SendResult, error) {
	pendingResp, err := client.ChatPending(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting pending chats: %w", err)
	}

	for _, p := range pendingResp.Pending {
		for _, participant := range p.Participants {
			if participant == targetAlias {
				return &SendResult{
					SessionID:     p.SessionID,
					Status:        "pending",
					TargetAgent:   targetAlias,
					Reply:         p.LastMessage,
					SenderWaiting: p.SenderWaiting,
					Events: []Event{
						{
							Type:      "message",
							FromAgent: p.LastFrom,
							Body:      p.LastMessage,
							Timestamp: p.LastActivity,
						},
					},
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no pending conversation with %s", targetAlias)
}
