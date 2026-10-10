package crypto_test

import (
	"bytes"
	"testing"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

func TestAADBytesIsDeterministicAndUnambiguous(t *testing.T) {
	a := crypto.AAD{UserID: "u1", Kind: "connection", RecordID: "c1", App: "github"}
	if !bytes.Equal(a.Bytes(), a.Bytes()) {
		t.Fatal("Bytes must be deterministic")
	}

	// Moving a character across a field boundary must change the encoding:
	// naive concatenation would make these two collide.
	x := crypto.AAD{UserID: "ab", Kind: "c", RecordID: "r", App: "a"}
	y := crypto.AAD{UserID: "a", Kind: "bc", RecordID: "r", App: "a"}
	if bytes.Equal(x.Bytes(), y.Bytes()) {
		t.Fatal("field boundaries are ambiguous")
	}

	variants := []crypto.AAD{
		{UserID: "u2", Kind: "connection", RecordID: "c1", App: "github"},
		{UserID: "u1", Kind: "approval", RecordID: "c1", App: "github"},
		{UserID: "u1", Kind: "connection", RecordID: "c2", App: "github"},
		{UserID: "u1", Kind: "connection", RecordID: "c1", App: "slack"},
		{UserID: "", Kind: "connection", RecordID: "c1", App: "github"},
		{UserID: "u1", Kind: "connection", RecordID: "c1", App: ""},
	}
	for i, v := range variants {
		if bytes.Equal(a.Bytes(), v.Bytes()) {
			t.Errorf("variant %d encodes identically to the original", i)
		}
	}
}

func TestAADValidateRequiresKindAndRecordID(t *testing.T) {
	ok := crypto.AAD{UserID: "", Kind: "signing_key", RecordID: "k1", App: ""}
	if err := ok.Validate(); err != nil {
		t.Fatalf("system records without user/app must be valid, got %v", err)
	}
	if err := (crypto.AAD{UserID: "u", RecordID: "r"}).Validate(); err == nil {
		t.Error("empty Kind must be rejected")
	}
	if err := (crypto.AAD{UserID: "u", Kind: "k"}).Validate(); err == nil {
		t.Error("empty RecordID must be rejected")
	}
}
