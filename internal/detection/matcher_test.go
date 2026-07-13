package detection

import (
	"testing"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

func TestMatchesOperators(t *testing.T) {
	event := model.Event{
		Kind:      model.EventExec,
		Process:   model.Process{PID: 42, UID: 1000, Name: "bash", Executable: "/tmp/tool", CommandLine: "bash -c id"},
		Container: model.Container{ID: "container-a"},
		Outcome:   model.Outcome{Success: true},
	}
	block := MatchBlock{
		All: []Condition{
			{Field: "kind", Op: "eq", Value: "process.exec"},
			{Field: "process.executable", Op: "prefix", Value: "/tmp/"},
			{Field: "process.executable", Op: "suffix", Value: "tool"},
			{Field: "process.command_line", Op: "contains", Value: "-C ID"},
			{Field: "process.name", Op: "in", Value: []interface{}{"sh", "bash"}},
			{Field: "process.pid", Op: "gte", Value: 40},
			{Field: "process.pid", Op: "lt", Value: 50},
			{Field: "container.id", Op: "exists", Value: true},
			{Field: "process.name", Op: "regex", Value: "^ba"},
			{Field: "process.uid", Op: "neq", Value: 0},
		},
	}
	if !Matches(event, block) {
		t.Fatal("expected all operators to match")
	}
	block.Any = []Condition{{Field: "process.name", Op: "eq", Value: "zsh"}, {Field: "process.pid", Op: "lte", Value: 42}}
	if !Matches(event, block) {
		t.Fatal("expected any condition to match")
	}
	block.Any = []Condition{{Field: "process.name", Op: "eq", Value: "zsh"}}
	if Matches(event, block) {
		t.Fatal("unexpected any-condition match")
	}
}

func TestConditionWithMissingFieldFailsClosed(t *testing.T) {
	event := model.Event{Kind: model.EventExec}
	if matchCondition(event, Condition{Field: "file.path", Op: "contains", Value: "/etc"}) {
		t.Fatal("missing field matched")
	}
}

func TestInvalidRegularExpressionFailsClosed(t *testing.T) {
	event := model.Event{Kind: model.EventExec, Process: model.Process{Name: "bash"}}
	condition := Condition{Field: "process.name", Op: "regex", Value: "["}
	if matchCondition(event, condition) {
		t.Fatal("invalid regular expression matched")
	}
}
