//go:build integration

package snapshot_test

import (
	"errors"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
)

// SetApprovalModes edits the approved review's modes without a new
// snapshot: the owner of a private server may, the owner of a published
// one may not (an admin does), and the approval record is kept.
func TestIntegrationSetApprovalModes(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	alice := newUser(t, st, "alice")
	bob := newUser(t, st, "bob")
	srv := newServer(t, st, alice, "notes")
	svc := snapshot.NewService(st, snapshot.WithClock(func() time.Time { return time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC) }))
	owner := snapshot.Actor{UserID: alice}

	if _, _, err := svc.SetApprovalModes(ctx, owner, srv, map[string]snapshot.Approval{"save": snapshot.ApprovalAuto}); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Errorf("before any approval: %v, want ErrNoSnapshot", err)
	}
	if _, err := svc.Create(ctx, owner, srv, v1Tools()); err != nil {
		t.Fatal(err)
	}
	approved, err := svc.Approve(ctx, owner, srv, 1, snapshot.ReviewDecisions{EnableReads: true, Tools: map[string]snapshot.Decision{
		"save": {Enabled: yes()}, "purge": {Enabled: yes()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if approved.Review["save"].Mode() != snapshot.ApprovalAsk {
		t.Fatalf("save after approval = %+v, want ask", approved.Review["save"])
	}

	rec, changed, err := svc.SetApprovalModes(ctx, owner, srv, map[string]snapshot.Approval{"save": snapshot.ApprovalAuto, "purge": snapshot.ApprovalAuto})
	if err != nil {
		t.Fatalf("owner SetApprovalModes: %v", err)
	}
	if changed != 2 || rec.Review["save"].Mode() != snapshot.ApprovalAuto || rec.Review["save"].ApprovalBy != alice {
		t.Errorf("after edit: changed %d, save %+v", changed, rec.Review["save"])
	}
	if rec.Version != approved.Version || rec.ApprovedBy != alice || !rec.ApprovedAt.Equal(*approved.ApprovedAt) {
		t.Errorf("approval record changed: v%d by %q at %v", rec.Version, rec.ApprovedBy, rec.ApprovedAt)
	}
	cur, err := svc.Current(ctx, owner, srv)
	if err != nil {
		t.Fatal(err)
	}
	if got := cur.Review.AutoRunWrites(); len(got) != 2 {
		t.Errorf("stored AutoRunWrites = %v", got)
	}
	if !cur.Review["search"].Enabled || cur.Content == nil {
		t.Errorf("edit lost the rest of the review: %+v / %+v", cur.Review["search"], cur.Content)
	}

	// Another user cannot see the private server.
	if _, _, err := svc.SetApprovalModes(ctx, snapshot.Actor{UserID: bob}, srv, map[string]snapshot.Approval{"save": snapshot.ApprovalAsk}); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Errorf("stranger: %v, want ErrNoSnapshot", err)
	}
	// Unknown tools and invalid modes change nothing.
	if _, _, err := svc.SetApprovalModes(ctx, owner, srv, map[string]snapshot.Approval{"nope": snapshot.ApprovalAuto}); !errors.Is(err, snapshot.ErrUnknownTool) {
		t.Errorf("unknown tool: %v", err)
	}

	// Published: the owner may no longer change modes; an admin may.
	publish(t, st, srv, bob)
	if _, _, err := svc.SetApprovalModes(ctx, owner, srv, map[string]snapshot.Approval{"save": snapshot.ApprovalAsk}); !errors.Is(err, snapshot.ErrReviewNotAllowed) {
		t.Errorf("owner of a published server: %v, want ErrReviewNotAllowed", err)
	}
	admin := snapshot.Actor{UserID: bob, Admin: true}
	rec, changed, err = svc.SetApprovalModes(ctx, admin, srv, map[string]snapshot.Approval{"save": snapshot.ApprovalAsk})
	if err != nil || changed != 1 || rec.Review["save"].Mode() != snapshot.ApprovalAsk || rec.Review["save"].ApprovalBy != bob {
		t.Errorf("admin edit: %v, changed %d, save %+v", err, changed, rec.Review["save"])
	}
}
