package run

import (
	"context"
	"errors"
	"io"
	"time"

	awid "github.com/awebai/aw/awid"
)

type EventStreamOpener func(ctx context.Context, deadline time.Time) (awid.EventSource, error)

type ClientWakeStream struct {
	Open          EventStreamOpener
	Now           func() time.Time
	RetryDelay    time.Duration
	MaxRetryDelay time.Duration
}

func NewClientWakeStream(client *awid.Client) *ClientWakeStream {
	return &ClientWakeStream{
		Open: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			return client.EventStream(ctx, deadline)
		},
	}
}

func (s *ClientWakeStream) Stream(ctx context.Context, deadline time.Time) (<-chan awid.AgentEvent, <-chan error) {
	events := make(chan awid.AgentEvent, 32)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		defer close(errs)
		if err := s.stream(ctx, deadline, events); err != nil && ctx.Err() == nil {
			errs <- err
		}
	}()

	return events, errs
}

var errStreamClosedEarly = errors.New("aweb: event stream closed before deadline")

const deadlineGrace = 100 * time.Millisecond

func (s *ClientWakeStream) stream(ctx context.Context, deadline time.Time, events chan<- awid.AgentEvent) error {
	if s == nil || s.Open == nil {
		return errors.New("aweb/run: wake stream opener is nil")
	}
	nowFn := s.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	delay := s.RetryDelay
	if delay <= 0 {
		delay = 250 * time.Millisecond
	}
	maxDelay := s.MaxRetryDelay
	if maxDelay <= 0 {
		maxDelay = 2 * time.Second
	}

	for {
		if ctx.Err() != nil {
			return nil
		}
		if !deadline.IsZero() && !nowFn().Before(deadline) {
			return nil
		}

		stream, err := s.Open(ctx, deadline)
		if err != nil {
			if code, ok := awid.HTTPStatusCode(err); ok && code >= 400 && code < 500 {
				return err
			}
			if !sleepForRetry(ctx, nowFn, deadline, delay) {
				return nil
			}
			delay = nextRetryDelay(delay, maxDelay)
			continue
		}

		delay = s.RetryDelay
		if delay <= 0 {
			delay = 250 * time.Millisecond
		}

		err = s.forwardEvents(ctx, nowFn, deadline, stream, events)
		_ = stream.Close()
		if err == nil {
			return nil
		}
		if errors.Is(err, errStreamClosedEarly) {
			if !sleepForRetry(ctx, nowFn, deadline, delay) {
				return nil
			}
			delay = nextRetryDelay(delay, maxDelay)
			continue
		}
		if ctx.Err() != nil {
			return nil
		}
		if !sleepForRetry(ctx, nowFn, deadline, delay) {
			return nil
		}
		delay = nextRetryDelay(delay, maxDelay)
	}
}

func (s *ClientWakeStream) forwardEvents(ctx context.Context, nowFn func() time.Time, deadline time.Time, stream awid.EventSource, events chan<- awid.AgentEvent) error {
	for {
		ev, err := stream.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				if deadlineReached(nowFn, deadline) {
					return nil
				}
				return errStreamClosedEarly
			}
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case events <- *ev:
		}
	}
}

func nextRetryDelay(delay, maxDelay time.Duration) time.Duration {
	next := delay * 2
	if next <= 0 {
		return maxDelay
	}
	if next > maxDelay {
		return maxDelay
	}
	return next
}

func sleepForRetry(ctx context.Context, nowFn func() time.Time, deadline time.Time, delay time.Duration) bool {
	if !deadline.IsZero() {
		remaining := deadline.Sub(nowFn())
		if remaining <= 0 {
			return false
		}
		if delay > remaining {
			delay = remaining
		}
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func deadlineReached(nowFn func() time.Time, deadline time.Time) bool {
	if deadline.IsZero() {
		return false
	}
	return !nowFn().Before(deadline.Add(-deadlineGrace))
}
