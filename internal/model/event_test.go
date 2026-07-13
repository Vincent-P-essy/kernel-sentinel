package model

import (
	"testing"
	"time"
)

func TestEnsureDefaultsAndFields(t *testing.T) {
	now := time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)
	event := Event{
		Timestamp: now.Add(-time.Second),
		Kind:      EventFileOpen,
		Process:   Process{PID: 42, TID: 43, UID: 1000, Name: "cat"},
		File:      &File{Path: "/tmp/value", Flags: 65},
		Network:   &Network{Address: "203.0.113.1", Port: 443},
		Outcome:   Outcome{Success: true},
	}
	event.EnsureDefaults(now)

	if event.SchemaVersion != "1.0" || event.ID == "" || !event.ObservedAt.Equal(now) {
		t.Fatalf("defaults not assigned: %#v", event)
	}
	tests := map[string]interface{}{
		"process.pid":      int64(42),
		"process.name":     "cat",
		"file.path":        "/tmp/value",
		"file.write":       true,
		"file.create":      true,
		"file.truncate":    false,
		"network.external": true,
		"outcome.success":  true,
	}
	for field, expected := range tests {
		actual, ok := event.Field(field)
		if !ok || actual != expected {
			t.Errorf("field %s = %#v, %v; want %#v", field, actual, ok, expected)
		}
	}
	if _, ok := event.Field("missing"); ok {
		t.Fatal("unknown field unexpectedly exists")
	}
	if value := FieldString(event, "process.pid"); value != "42" {
		t.Fatalf("FieldString process.pid = %q", value)
	}
}

func TestNetworkExternalRejectsPrivateAndInvalidAddresses(t *testing.T) {
	for _, address := range []string{"10.2.3.4", "127.0.0.1", "not-an-ip"} {
		event := Event{Network: &Network{Address: address}}
		actual, ok := event.Field("network.external")
		if !ok || actual != false {
			t.Errorf("address %s classified external", address)
		}
	}
}

func TestForkEventKind(t *testing.T) {
	event := Event{Kind: EventFork, Process: Process{PID: 2, PPID: 1, ParentName: "init"}}
	if kind, ok := event.Field("kind"); !ok || kind != "process.fork" {
		t.Fatalf("fork kind = %#v, %v", kind, ok)
	}
	if ppid, ok := event.Field("process.ppid"); !ok || ppid != int64(1) {
		t.Fatalf("fork parent = %#v, %v", ppid, ok)
	}
}
