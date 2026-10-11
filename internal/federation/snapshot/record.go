package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrCorrupt: a stored snapshot row does not decode.
var ErrCorrupt = errors.New("snapshot: stored snapshot does not decode")

// Record is a stored snapshot: its row metadata, capability set and review.
// ApprovedBy is empty for system approvals and unapproved snapshots.
type Record struct {
	ID           string
	ServerID     string
	Version      int
	Status       string
	DiscoveredAt time.Time
	ApprovedBy   string
	ApprovedAt   *time.Time
	Snapshot     *Snapshot
	Review       Review
}

// encodeSnapshot builds the pending store row for snap (empty lists are
// stored as []).
func encodeSnapshot(serverID string, snap *Snapshot) (*store.MCPSnapshot, error) {
	row := &store.MCPSnapshot{ServerID: serverID, Status: store.MCPSnapshotPending}
	var err error
	if row.Tools, err = marshalList(snap.Tools); err != nil {
		return nil, err
	}
	if row.Resources, err = marshalList(snap.Resources); err != nil {
		return nil, err
	}
	if row.ResourceTemplates, err = marshalList(snap.ResourceTemplates); err != nil {
		return nil, err
	}
	if row.Prompts, err = marshalList(snap.Prompts); err != nil {
		return nil, err
	}
	return row, nil
}

func marshalList[T any](xs []T) (json.RawMessage, error) {
	if xs == nil {
		xs = []T{}
	}
	b, err := json.Marshal(xs)
	if err != nil {
		return nil, fmt.Errorf("snapshot: encode: %w", err)
	}
	return b, nil
}

// encodeReview encodes r for the review column (nil = {}).
func encodeReview(r Review) (json.RawMessage, error) {
	if r == nil {
		r = Review{}
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("snapshot: encode review: %w", err)
	}
	return b, nil
}

// decodeRecord decodes a stored snapshot row.
func decodeRecord(row *store.MCPSnapshot) (*Record, error) {
	rec := &Record{
		ID: row.ID, ServerID: row.ServerID, Version: row.Version, Status: row.Status,
		DiscoveredAt: row.DiscoveredAt, ApprovedAt: row.ApprovedAt,
		Snapshot: &Snapshot{}, Review: Review{},
	}
	if row.ApprovedBy != nil {
		rec.ApprovedBy = *row.ApprovedBy
	}
	for _, f := range []struct {
		raw json.RawMessage
		dst any
	}{
		{row.Tools, &rec.Snapshot.Tools},
		{row.Resources, &rec.Snapshot.Resources},
		{row.ResourceTemplates, &rec.Snapshot.ResourceTemplates},
		{row.Prompts, &rec.Snapshot.Prompts},
		{row.Review, &rec.Review},
	} {
		if normNull(f.raw) == nil {
			continue
		}
		if err := json.Unmarshal(f.raw, f.dst); err != nil {
			return nil, ErrCorrupt
		}
	}
	if rec.Review == nil {
		rec.Review = Review{}
	}
	return rec, nil
}
