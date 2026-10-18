package audit

import (
	"context"
	"errors"
	"testing"
	"time"
)

type purgeCall struct {
	olderThan time.Time
	limit     int
}

type countMetrics struct{ n int }

func (m *countMetrics) AuditPurged(n int) { m.n += n }

type memRecorder struct{ events []Event }

func (r *memRecorder) Record(_ context.Context, ev Event) error {
	r.events = append(r.events, ev)
	return nil
}

func TestPurgeJobBatchesUntilShortBatch(t *testing.T) {
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	var calls []purgeCall
	results := []int64{3, 3, 1}
	purge := func(_ context.Context, olderThan time.Time, limit int) (int64, error) {
		calls = append(calls, purgeCall{olderThan, limit})
		return results[len(calls)-1], nil
	}
	m := &countMetrics{}
	rec := &memRecorder{}
	j, err := newPurgeJob(purge, PurgeOptions{Retention: 48 * time.Hour, BatchSize: 3, Metrics: m, Recorder: rec, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if j.Name() != "audit.purge" || j.Interval() != 24*time.Hour {
		t.Errorf("Name/Interval = %q/%v", j.Name(), j.Interval())
	}
	if err := j.Run(t.Context()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(calls) != 3 {
		t.Fatalf("%d batches, want 3", len(calls))
	}
	for _, c := range calls {
		if !c.olderThan.Equal(now.Add(-48*time.Hour)) || c.limit != 3 {
			t.Errorf("batch = %+v, want cutoff now-48h, limit 3", c)
		}
	}
	if m.n != 7 {
		t.Errorf("metrics = %d, want 7", m.n)
	}
	if len(rec.events) != 1 {
		t.Fatalf("%d events, want 1", len(rec.events))
	}
	ev := rec.events[0]
	if ev.UserID != "" || ev.ResourceIdentity["action"] != "audit.purged" || ev.ResourceIdentity["deleted"] != "7" || ev.Outcome != "succeeded" {
		t.Errorf("event = %+v", ev)
	}
}

func TestPurgeJobNothingToDeleteRecordsNoEvent(t *testing.T) {
	rec := &memRecorder{}
	j, err := newPurgeJob(func(context.Context, time.Time, int) (int64, error) { return 0, nil }, PurgeOptions{Retention: time.Hour, Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(rec.events) != 0 {
		t.Errorf("events = %v, want none", rec.events)
	}
}

func TestPurgeJobErrorKeepsCommittedCount(t *testing.T) {
	calls := 0
	boom := errors.New("boom")
	purge := func(context.Context, time.Time, int) (int64, error) {
		calls++
		if calls == 2 {
			return 0, boom
		}
		return 2, nil
	}
	rec := &memRecorder{}
	j, err := newPurgeJob(purge, PurgeOptions{Retention: time.Hour, BatchSize: 2, Recorder: rec})
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Run(t.Context()); !errors.Is(err, boom) {
		t.Fatalf("Run = %v, want boom", err)
	}
	if len(rec.events) != 1 || rec.events[0].Outcome != "partial" || rec.events[0].ResourceIdentity["deleted"] != "2" {
		t.Errorf("events = %+v, want one partial with deleted=2", rec.events)
	}
}

func TestPurgeJobRequiresRetention(t *testing.T) {
	if _, err := newPurgeJob(func(context.Context, time.Time, int) (int64, error) { return 0, nil }, PurgeOptions{}); err == nil {
		t.Error("zero retention accepted")
	}
	if _, err := NewPurgeJob(nil, PurgeOptions{Retention: time.Hour}); err == nil {
		t.Error("nil store accepted")
	}
}
