package detection

import (
	"testing"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

func sequenceRule() Rule {
	return Rule{
		ID: "KS-SEQUENCE-TEST", Title: "sequence", Description: "sequence", Severity: "high", Score: 80,
		MITRE: []string{"T1000"}, Within: Duration{10 * time.Second}, GroupBy: "process.pid",
		Sequence: []SequenceStep{
			{Name: "exec", Match: MatchBlock{All: []Condition{{Field: "kind", Op: "eq", Value: "process.exec"}}}},
			{Name: "connect", Match: MatchBlock{All: []Condition{{Field: "kind", Op: "eq", Value: "network.connect"}}}},
		},
	}
}

func TestEngineCompletesTemporalSequence(t *testing.T) {
	base := time.Now()
	engine := NewEngine([]Rule{sequenceRule()}, false)
	execEvent := model.Event{ID: "one", Timestamp: base, ObservedAt: base, Kind: model.EventExec, Process: model.Process{PID: 7}}
	connectEvent := model.Event{ID: "two", Timestamp: base.Add(time.Second), ObservedAt: base, Kind: model.EventConnect, Process: model.Process{PID: 7}}

	if alerts := engine.Process(execEvent); len(alerts) != 0 {
		t.Fatalf("sequence fired early: %v", alerts)
	}
	alerts := engine.Process(connectEvent)
	if len(alerts) != 1 || len(alerts[0].Evidence) != 2 || alerts[0].Entity != "7" {
		t.Fatalf("unexpected sequence alerts: %#v", alerts)
	}
}

func TestEngineDoesNotCrossEntityOrTimeBoundary(t *testing.T) {
	base := time.Now()
	engine := NewEngine([]Rule{sequenceRule()}, false)
	engine.Process(model.Event{Timestamp: base, Kind: model.EventExec, Process: model.Process{PID: 7}})
	if alerts := engine.Process(model.Event{Timestamp: base.Add(time.Second), Kind: model.EventConnect, Process: model.Process{PID: 8}}); len(alerts) != 0 {
		t.Fatal("sequence crossed process boundary")
	}
	if alerts := engine.Process(model.Event{Timestamp: base.Add(20 * time.Second), Kind: model.EventConnect, Process: model.Process{PID: 7}}); len(alerts) != 0 {
		t.Fatal("expired sequence fired")
	}
}

func TestBehaviorScorerCombinesIndependentSignals(t *testing.T) {
	base := time.Now()
	engine := NewEngine(nil, true)
	container := model.Container{ID: "container-a"}
	first := model.Event{
		Timestamp: base, Kind: model.EventExec, Process: model.Process{PID: 10, Executable: "/tmp/tool"},
		Container: container, Outcome: model.Outcome{Success: true},
	}
	second := model.Event{
		Timestamp: base.Add(time.Second), Kind: model.EventFileOpen, Process: model.Process{PID: 11},
		File: &model.File{Path: "/etc/shadow"}, Container: container, Outcome: model.Outcome{Success: true},
	}
	if alerts := engine.Process(first); len(alerts) != 0 {
		t.Fatal("single signal exceeded threshold")
	}
	alerts := engine.Process(second)
	if len(alerts) != 1 || alerts[0].RuleID != "KS-BEHAVIOR-001" || alerts[0].Score < 60 {
		t.Fatalf("unexpected behavior alert: %#v", alerts)
	}
}

func TestEnginePrunesInactiveSequenceAndBehaviorState(t *testing.T) {
	base := time.Now()
	engine := NewEngine([]Rule{sequenceRule()}, true)
	engine.Process(model.Event{Timestamp: base, Kind: model.EventExec, Process: model.Process{PID: 7}})
	engine.scorer.Process(model.Event{Timestamp: base, Kind: model.EventExec, Process: model.Process{PID: 8}}, base)
	if len(engine.states) == 0 || len(engine.scorer.profiles) == 0 {
		t.Fatal("test setup did not create state")
	}
	engine.prune(base.Add(30 * time.Minute))
	if len(engine.states) != 0 || len(engine.scorer.profiles) != 0 {
		t.Fatalf("inactive state retained: sequences=%#v profiles=%#v", engine.states, engine.scorer.profiles)
	}
}
