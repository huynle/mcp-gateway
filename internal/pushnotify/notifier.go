package pushnotify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/webpush"
)

// Message is the push payload the service worker shows (sw.js "push"):
// exactly these four fields. URL is a same-origin path.
type Message struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"`
	Tag   string `json:"tag"`
}

// ApprovalMessage is the notification for a pending approval: the tool
// and the account label, nothing else. Arguments, the resource identity
// and the connected account's name stay on the approvals page (push
// services see message metadata, and the text sits on the device).
func ApprovalMessage(a approvals.Approval) Message {
	body := a.Tool
	if a.AccountLabel != "" {
		body += " (" + a.AccountLabel + ")"
	}
	return Message{Title: "Approval needed", Body: body, URL: "/approvals", Tag: "approval-" + a.ID}
}

// testMessage is SendTest's notification.
var testMessage = Message{
	Title: "Test notification", Body: "Notifications from MCP Gateway work on this device.",
	URL: "/account#notifications", Tag: "test",
}

// Notify implements approvals.Notifier: the approval's message to every
// device of its user, within the timeout. A user without devices costs
// one query. Gone subscriptions are deleted; the other failures are
// returned joined (the approvals service logs them and never fails the
// approval). Errors never name an endpoint.
func (s *Service) Notify(ctx context.Context, a approvals.Approval) error {
	ttl := a.ExpiresAt.Sub(s.now())
	ttl = min(max(ttl, MinTTL), MaxTTL)
	_, err := s.send(ctx, a.UserID, ApprovalMessage(a), webpush.SendOptions{TTL: ttl, Urgency: "high", Topic: topic(a.ID)})
	if err != nil {
		return fmt.Errorf("web push: approval %s: %w", a.ID, err)
	}
	return nil
}

// SendTest sends the test notification to every device of userID and
// returns how many accepted it. At most once per TestInterval per user
// (TestTooSoonError); the limit is per process.
func (s *Service) SendTest(ctx context.Context, userID string) (int, error) {
	now := s.now()
	s.testMu.Lock()
	if last, ok := s.lastTest[userID]; ok && now.Sub(last) < TestInterval {
		s.testMu.Unlock()
		return 0, &TestTooSoonError{RetryAfter: TestInterval - now.Sub(last)}
	}
	for u, t := range s.lastTest {
		if now.Sub(t) >= TestInterval {
			delete(s.lastTest, u) // keep the map to the users of the last interval
		}
	}
	s.lastTest[userID] = now
	s.testMu.Unlock()
	n, err := s.send(ctx, userID, testMessage, webpush.SendOptions{TTL: testTTL, Urgency: "normal"})
	s.record(ctx, userID, ActionTestSent, nil, map[string]string{"sent": fmt.Sprint(n)})
	return n, err
}

// target is one decrypted subscription.
type target struct {
	id  string
	sub webpush.Subscription
}

// outcome is one send's result.
type outcome struct {
	id  string
	err error
}

// send delivers msg to every device of userID: at most NotifyConcurrency
// at a time, all within s.timeout. Results that are not back by then
// count as timed out and are not waited for (a sender that ignores its
// context cannot hold the caller). It returns how many succeeded.
func (s *Service) send(parent context.Context, userID string, msg Message, opts webpush.SendOptions) (int, error) {
	ctx, cancel := context.WithTimeout(parent, s.timeout)
	defer cancel()
	targets, errs := s.targets(ctx, userID)
	if len(targets) == 0 {
		return 0, errors.Join(errs...)
	}
	sender, err := s.senderFor(ctx)
	if err != nil {
		return 0, errors.Join(append(errs, err)...)
	}
	payload, err := json.Marshal(msg)
	if err != nil {
		return 0, err
	}
	results := make(chan outcome, len(targets)) // buffered: late senders never block
	slots := make(chan struct{}, NotifyConcurrency)
	go func() {
		for _, t := range targets {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				return
			}
			go func() {
				defer func() { <-slots }()
				results <- outcome{id: t.id, err: sender.Send(ctx, t.sub, payload, opts)}
			}()
		}
	}()
	done := map[string]error{}
collect:
	for len(done) < len(targets) {
		select {
		case r := <-results:
			done[r.id] = r.err
		case <-ctx.Done():
			break collect
		}
	}
	for _, t := range targets {
		if _, ok := done[t.id]; !ok {
			done[t.id] = ctx.Err()
		}
	}
	n, sendErrs := s.settle(parent, userID, done)
	return n, errors.Join(append(errs, sendErrs...)...)
}

// targets loads and opens userID's subscriptions. A row that does not
// open (moved between users, tampered) is reported and skipped.
func (s *Service) targets(ctx context.Context, userID string) ([]target, []error) {
	var rows []store.PushSubscription
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		var err error
		rows, err = tx.List(ctx, userID)
		return err
	})
	if err != nil {
		return nil, []error{fmt.Errorf("load subscriptions: %w", err)}
	}
	var out []target
	var errs []error
	for _, r := range rows {
		plain, err := crypto.Decrypt(ctx, s.kp, s.aad(userID, r.ID), crypto.Envelope(r.Sealed))
		if err != nil {
			errs = append(errs, fmt.Errorf("subscription %s: open: %w", r.ID, err))
			continue
		}
		var sealed sealedSubscription
		err = json.Unmarshal(plain, &sealed)
		clear(plain)
		if err != nil {
			errs = append(errs, fmt.Errorf("subscription %s: decode", r.ID))
			continue
		}
		out = append(out, target{id: r.ID, sub: webpush.Subscription{Endpoint: sealed.Endpoint, P256dh: sealed.P256dh, Auth: sealed.Auth}})
	}
	return out, errs
}

// settle records every result on its row in one user-scoped transaction:
// gone subscriptions (404/410) are deleted, successes and failures
// counted. It runs on its own short deadline so the bookkeeping happens
// even after the fan-out used up its timeout. It returns the number of
// successes and the failures (gone subscriptions are not failures).
func (s *Service) settle(parent context.Context, userID string, done map[string]error) (int, []error) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), recordTimeout)
	defer cancel()
	now := s.now()
	ok, removed := 0, 0
	var errs []error
	err := s.st.AsUser(ctx, userID, func(tx Tx) error {
		for id, sendErr := range done {
			switch {
			case sendErr == nil:
				ok++
				if err := tx.RecordDelivery(ctx, id, true, now); err != nil {
					return err
				}
			case gone(sendErr):
				removed++
				if _, err := tx.Delete(ctx, id); err != nil {
					return err
				}
			default:
				errs = append(errs, fmt.Errorf("subscription %s: %w", id, sendErr))
				if err := tx.RecordDelivery(ctx, id, false, now); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		s.log.Warn("push deliveries not recorded", "event", "pushnotify.record_failed", "user_id", userID,
			"error", observability.RedactError(err), observability.RequestIDAttr(parent))
	}
	s.log.Info("push notifications sent", "event", "pushnotify.sent", "user_id", userID,
		"delivered", ok, "gone", removed, "failed", len(errs), observability.RequestIDAttr(parent))
	return ok, errs
}

// gone reports whether the push service said the subscription no longer
// exists (404 or 410; webpush.ErrGone).
func gone(err error) bool {
	var se *webpush.StatusError
	return errors.Is(err, webpush.ErrGone) ||
		(errors.As(err, &se) && (se.StatusCode == http.StatusNotFound || se.StatusCode == http.StatusGone))
}
