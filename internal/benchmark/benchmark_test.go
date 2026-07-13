package benchmark

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

func TestRepositoryBenchmarkDetectsAllScenariosWithoutBenignAlerts(t *testing.T) {
	rules, err := detection.LoadRules("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	report, err := Run(rules, "../../lab/events/attack-suite.jsonl", "../../lab/events/benign-suite.jsonl", "../../lab/ground-truth.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Techniques != 20 || report.Summary.Recall != 1 || report.Summary.FalsePositives != 0 {
		t.Fatalf("unexpected benchmark: %#v", report.Summary)
	}
	paths, err := Write(report, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		if info, err := os.Stat(path); err != nil || info.Size() == 0 {
			t.Fatalf("missing report %s: %v", path, err)
		}
	}
}

func TestGroundTruthValidationAndBadEvent(t *testing.T) {
	directory := t.TempDir()
	truth := filepath.Join(directory, "truth.yaml")
	if err := os.WriteFile(truth, []byte("schema_version: \"1.0\"\ntechniques: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadTruth(truth); err == nil {
		t.Fatal("empty truth accepted")
	}
	events := filepath.Join(directory, "events.jsonl")
	encoded, _ := json.Marshal(map[string]string{"kind": "process.exec"})
	if err := os.WriteFile(events, append(encoded, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEvents(events); err == nil {
		t.Fatal("event without timestamp accepted")
	}
}

func TestLiveAlertEvaluationSeparatesCausalAttributionFromRulePresence(t *testing.T) {
	directory := t.TempDir()
	truthPath := filepath.Join(directory, "truth.yaml")
	truth := `schema_version: "1.0"
techniques:
  - {scenario_id: attributed, technique: T1000, title: Attributed alert, expected_rules: [KS-LIVE-001]}
  - {scenario_id: presence, technique: T2000, title: Presence-only alert, expected_rules: [KS-LIVE-002]}
  - {scenario_id: missing, technique: T3000, title: Incorrectly attributed alert, expected_rules: [KS-LIVE-003]}
`
	if err := os.WriteFile(truthPath, []byte(truth), 0o600); err != nil {
		t.Fatal(err)
	}
	alertPath := filepath.Join(directory, "alerts.jsonl")
	now := time.Date(2026, time.July, 12, 10, 0, 0, 0, time.UTC)
	alerts := []model.Alert{
		{
			RuleID:           "KS-LIVE-001",
			ScenarioIDs:      []string{"attributed"},
			DetectionLatency: 12,
			Evidence:         []model.Event{{Kind: model.EventExec}},
		},
		{
			RuleID:           "KS-LIVE-002",
			DetectionLatency: 34,
			Evidence:         []model.Event{{Kind: model.EventFileOpen}},
		},
		{
			RuleID:           "KS-LIVE-003",
			ScenarioIDs:      []string{"another-scenario"},
			DetectionLatency: 56,
			DetectedAt:       now,
		},
	}
	file, err := os.Create(alertPath)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(file)
	for _, alert := range alerts {
		if err := encoder.Encode(alert); err != nil {
			file.Close()
			t.Fatal(err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	report, err := RunLiveAlerts(7, alertPath, truthPath)
	if err != nil {
		t.Fatal(err)
	}
	if report.Evaluation.Mode != "live_alerts" || report.Evaluation.AlertsWithoutScenarioID != 1 {
		t.Fatalf("unexpected evaluation metadata: %#v", report.Evaluation)
	}
	if report.Summary.Detected != 2 || report.Summary.Attributed != 1 || report.Summary.RulePresenceOnly != 1 {
		t.Fatalf("unexpected live summary: %#v", report.Summary)
	}
	if report.Matrix[0].Attribution != "scenario_id" || !report.Matrix[0].CausallyAttributed {
		t.Fatalf("explicit scenario attribution lost: %#v", report.Matrix[0])
	}
	if report.Matrix[1].Attribution != "rule_id_presence" || report.Matrix[1].CausallyAttributed {
		t.Fatalf("presence-only result overclaimed causality: %#v", report.Matrix[1])
	}
	if report.Matrix[2].Detected || report.Matrix[2].Attribution != "none" {
		t.Fatalf("alert assigned to another scenario was reused: %#v", report.Matrix[2])
	}

	paths, err := Write(report, filepath.Join(directory, "report"))
	if err != nil {
		t.Fatal(err)
	}
	markdown, err := os.ReadFile(paths["markdown"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(markdown), "do not establish") || !strings.Contains(string(markdown), "rule_id presence only") {
		t.Fatalf("live limitations missing from markdown:\n%s", markdown)
	}
	csvReport, err := os.ReadFile(paths["csv"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(csvReport), "attribution,causally_attributed") || !strings.Contains(string(csvReport), "rule_id_presence,false") {
		t.Fatalf("live attribution missing from CSV:\n%s", csvReport)
	}
	jsonReport, err := os.ReadFile(paths["json"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonReport), `"mode": "live_alerts"`) || !strings.Contains(string(jsonReport), `"causally_attributed": false`) {
		t.Fatalf("live attribution missing from JSON:\n%s", jsonReport)
	}
}

func TestLiveAlertEvaluationRejectsAlertWithoutRuleID(t *testing.T) {
	directory := t.TempDir()
	truthPath := filepath.Join(directory, "truth.yaml")
	if err := os.WriteFile(truthPath, []byte("schema_version: \"1.0\"\ntechniques:\n  - {scenario_id: one, technique: T1000, title: One, expected_rules: [KS-ONE]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alertPath := filepath.Join(directory, "alerts.jsonl")
	if err := os.WriteFile(alertPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunLiveAlerts(1, alertPath, truthPath); err == nil || !strings.Contains(err.Error(), "has no rule_id") {
		t.Fatalf("alert without rule_id accepted: %v", err)
	}
}
