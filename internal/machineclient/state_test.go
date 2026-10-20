//go:build !windows

package machineclient

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testMachineID = "0b9a3f4e-2c1d-4e5f-8a7b-6c5d4e3f2a1b"

func TestStateRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cfg")
	st := &State{Gateway: "https://g.example.com", MachineID: testMachineID, Name: "huy-mac", KeyStore: KeyStoreFile}
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(dir, "machine.json"))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("%v %v", err, fi)
	}
	got, err := LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if *got != *st {
		t.Fatalf("got %+v", got)
	}
	if err := DeleteState(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatalf("after delete: %v", err)
	}
	if err := DeleteState(dir); err != nil {
		t.Fatalf("delete missing: %v", err)
	}
}

func TestLoadStateRejects(t *testing.T) {
	for name, content := range map[string]string{
		"unknown field": `{"gateway":"https://g.example.com","machine_id":"` + testMachineID + `","name":"a","key_store":"file","token":"x"}`,
		"bad gateway":   `{"gateway":"http://g.example.com","machine_id":"` + testMachineID + `","name":"a","key_store":"file"}`,
		"bad id":        `{"gateway":"https://g.example.com","machine_id":"nope","name":"a","key_store":"file"}`,
		"bad store":     `{"gateway":"https://g.example.com","machine_id":"` + testMachineID + `","name":"a","key_store":"vault"}`,
		"bad name":      `{"gateway":"https://g.example.com","machine_id":"` + testMachineID + `","name":"A B","key_store":"file"}`,
		"not json":      `nope`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "machine.json"), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadState(dir); err == nil || errors.Is(err, ErrNotLoggedIn) {
				t.Fatalf("err %v", err)
			}
		})
	}
	dir := t.TempDir()
	st := &State{Gateway: "https://g.example.com", MachineID: testMachineID, Name: "a", KeyStore: KeyStoreFile}
	if err := SaveState(dir, st); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "machine.json"), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(dir); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("world-writable state accepted: %v", err)
	}
}
