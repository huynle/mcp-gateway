package audit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	uuidUser = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	uuidTok  = "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	uuidConn = "2b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	uuidPol  = "3b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	uuidAppr = "4b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	uuidOp   = "5b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
)

func TestToStoreEventMapsEveryField(t *testing.T) {
	ev := Event{
		Time:             time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC),
		UserID:           uuidUser,
		TokenID:          uuidTok,
		Tool:             "github.create_issue",
		AccountID:        uuidConn,
		AccountLabel:     "company",
		ResourceIdentity: map[string]string{"repo": "acme/api"},
		Decision:         "allow",
		PolicyVersion:    uuidPol,
		ApprovalID:       uuidAppr,
		OperationID:      uuidOp,
		Outcome:          "succeeded",
		Latency:          1500 * time.Millisecond,
		RequestID:        "req-12345678",
		ErrorClass:       "",
	}
	se := toStoreEvent(ev)
	if se.EventType != EventTypeToolCall {
		t.Errorf("EventType = %q", se.EventType)
	}
	if se.UserID == nil || *se.UserID != uuidUser {
		t.Errorf("UserID = %v", se.UserID)
	}
	if se.TokenID == nil || *se.TokenID != uuidTok || se.ConnectionID == nil || *se.ConnectionID != uuidConn {
		t.Errorf("TokenID/ConnectionID = %v/%v", se.TokenID, se.ConnectionID)
	}
	if se.Tool == nil || *se.Tool != "github.create_issue" || se.AccountLabel == nil || *se.AccountLabel != "company" {
		t.Errorf("Tool/AccountLabel = %v/%v", se.Tool, se.AccountLabel)
	}
	if se.Decision != "allow" || se.Outcome == nil || *se.Outcome != "succeeded" {
		t.Errorf("Decision/Outcome = %q/%v", se.Decision, se.Outcome)
	}
	if se.PolicyVersionID == nil || *se.PolicyVersionID != uuidPol || se.ApprovalID == nil || *se.ApprovalID != uuidAppr || se.OperationID == nil || *se.OperationID != uuidOp {
		t.Errorf("ids = %v/%v/%v", se.PolicyVersionID, se.ApprovalID, se.OperationID)
	}
	if se.LatencyMS == nil || *se.LatencyMS != 1500 {
		t.Errorf("LatencyMS = %v", se.LatencyMS)
	}
	var res map[string]string
	if err := json.Unmarshal(se.Resource, &res); err != nil || res["repo"] != "acme/api" {
		t.Errorf("Resource = %s (%v)", se.Resource, err)
	}
	var det map[string]string
	if err := json.Unmarshal(se.Details, &det); err != nil || det["request_id"] != "req-12345678" {
		t.Errorf("Details = %s (%v)", se.Details, err)
	}
	if _, has := det["error_class"]; has {
		t.Error("empty error_class should be omitted from details")
	}
}

func TestToStoreEventSystemEventHasNoUser(t *testing.T) {
	se := toStoreEvent(Event{Decision: "auth_failed", ErrorClass: "token_expired", RequestID: "req-12345678"})
	if se.UserID != nil {
		t.Errorf("UserID = %v, want nil", *se.UserID)
	}
	if se.EventType != EventTypeSystem {
		t.Errorf("EventType = %q, want %q", se.EventType, EventTypeSystem)
	}
	for name, p := range map[string]*string{"TokenID": se.TokenID, "Tool": se.Tool, "ConnectionID": se.ConnectionID,
		"AccountLabel": se.AccountLabel, "PolicyVersionID": se.PolicyVersionID, "ApprovalID": se.ApprovalID,
		"OperationID": se.OperationID, "Outcome": se.Outcome} {
		if p != nil {
			t.Errorf("%s = %q, want nil for an unset field", name, *p)
		}
	}
	if se.LatencyMS != nil {
		t.Errorf("LatencyMS = %v, want nil", *se.LatencyMS)
	}
	var det map[string]string
	if err := json.Unmarshal(se.Details, &det); err != nil || det["error_class"] != "token_expired" {
		t.Errorf("Details = %s", se.Details)
	}
}

func TestToStoreEventUserEventWithoutTool(t *testing.T) {
	se := toStoreEvent(Event{UserID: uuidUser, Decision: "token.created"})
	if se.EventType != EventTypeUser {
		t.Errorf("EventType = %q, want %q", se.EventType, EventTypeUser)
	}
}

func TestToStoreEventRedactsAndCapsErrorClass(t *testing.T) {
	se := toStoreEvent(Event{Decision: "x", ErrorClass: "vendor: Bearer mgw_abc_secret " + strings.Repeat("y", 300)})
	var det map[string]string
	if err := json.Unmarshal(se.Details, &det); err != nil {
		t.Fatal(err)
	}
	ec := det["error_class"]
	if strings.Contains(ec, "mgw_abc") {
		t.Errorf("error_class carries a token: %q", ec)
	}
	if len(ec) > MaxErrorClassLen {
		t.Errorf("error_class length %d > %d", len(ec), MaxErrorClassLen)
	}
}

func TestToStoreEventAppliesResourceCaps(t *testing.T) {
	se := toStoreEvent(Event{UserID: uuidUser, Tool: "t", Decision: "allow",
		ResourceIdentity: map[string]string{"body": strings.Repeat("z", 1000)}})
	var res map[string]string
	if err := json.Unmarshal(se.Resource, &res); err != nil {
		t.Fatal(err)
	}
	if len(res["body"]) != MaxResourceValueLen {
		t.Errorf("resource value not capped: %d", len(res["body"]))
	}
}

func TestFromStoreEventRoundTrips(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	se := &store.AuditEvent{
		ID: "9b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d", EventType: EventTypeToolCall,
		UserID: ptr(uuidUser), TokenID: ptr(uuidTok), Tool: ptr("slack.post_message"), ConnectionID: ptr(uuidConn),
		AccountLabel: ptr("personal"), Resource: []byte(`{"channel":"C123"}`), Decision: "confirm",
		PolicyVersionID: ptr(uuidPol), ApprovalID: ptr(uuidAppr), OperationID: ptr(uuidOp), Outcome: ptr("unknown"),
		LatencyMS: ptr(42), Details: []byte(`{"request_id":"req-12345678","error_class":"timeout"}`), CreatedAt: now,
	}
	rec := fromStoreEvent(se)
	if rec.ID != se.ID || rec.EventType != EventTypeToolCall {
		t.Errorf("ID/EventType = %q/%q", rec.ID, rec.EventType)
	}
	want := Event{
		Time: now, UserID: uuidUser, TokenID: uuidTok, Tool: "slack.post_message", AccountID: uuidConn,
		AccountLabel: "personal", ResourceIdentity: map[string]string{"channel": "C123"}, Decision: "confirm",
		PolicyVersion: uuidPol, ApprovalID: uuidAppr, OperationID: uuidOp, Outcome: "unknown",
		Latency: 42 * time.Millisecond, RequestID: "req-12345678", ErrorClass: "timeout",
	}
	got := rec.Event
	if got.Time != want.Time || got.UserID != want.UserID || got.TokenID != want.TokenID || got.Tool != want.Tool ||
		got.AccountID != want.AccountID || got.AccountLabel != want.AccountLabel || got.Decision != want.Decision ||
		got.PolicyVersion != want.PolicyVersion || got.ApprovalID != want.ApprovalID || got.OperationID != want.OperationID ||
		got.Outcome != want.Outcome || got.Latency != want.Latency || got.RequestID != want.RequestID || got.ErrorClass != want.ErrorClass ||
		got.ResourceIdentity["channel"] != "C123" {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}

func TestFromStoreEventIgnoresUnknownDetails(t *testing.T) {
	se := &store.AuditEvent{Decision: "x", Details: []byte(`{"arguments":{"title":"leak"},"request_id":"r"}`), Resource: []byte(`{}`)}
	rec := fromStoreEvent(se)
	if rec.RequestID != "r" {
		t.Errorf("RequestID = %q", rec.RequestID)
	}
}

func TestPageDefaults(t *testing.T) {
	p := Page{}.normalize()
	if p.Limit != DefaultPageSize || p.Offset != 0 {
		t.Errorf("defaults = %+v", p)
	}
	p = Page{Limit: 10_000, Offset: -5}.normalize()
	if p.Limit != MaxPageSize || p.Offset != 0 {
		t.Errorf("clamped = %+v", p)
	}
}

func ptr[T any](v T) *T { return &v }
