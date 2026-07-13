package detection

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRepositoryRules(t *testing.T) {
	rules, err := LoadRules("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 20 {
		t.Fatalf("loaded %d rules, want 20", len(rules))
	}
}

func TestLoadRulesRejectsUnknownAndDuplicateFields(t *testing.T) {
	directory := t.TempDir()
	invalid := `rules:
  - id: KS-TEST-001
    title: test
    description: test
    severity: high
    score: 80
    mitre: [T1000]
    unexpected: true
    match:
      all: [{field: kind, op: eq, value: process.exec}]
`
	if err := os.WriteFile(filepath.Join(directory, "invalid.yaml"), []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRules(directory); err == nil || !strings.Contains(err.Error(), "field unexpected") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuleFailures(t *testing.T) {
	valid := Rule{
		ID: "KS-TEST-001", Title: "test", Description: "test", Severity: "high", Score: 80,
		MITRE: []string{"T1000"}, Match: &MatchBlock{All: []Condition{{Field: "kind", Op: "eq", Value: "process.exec"}}},
	}
	tests := []struct {
		name   string
		mutate func(*Rule)
	}{
		{"id", func(rule *Rule) { rule.ID = "bad" }},
		{"title", func(rule *Rule) { rule.Title = "" }},
		{"score", func(rule *Rule) { rule.Score = 101 }},
		{"severity", func(rule *Rule) { rule.Severity = "urgent" }},
		{"mitre", func(rule *Rule) { rule.MITRE = nil }},
		{"both modes", func(rule *Rule) { rule.Sequence = []SequenceStep{{Name: "x"}, {Name: "y"}} }},
		{"operator", func(rule *Rule) { rule.Match.All[0].Op = "magic" }},
		{"regex", func(rule *Rule) { rule.Match.All[0] = Condition{Field: "kind", Op: "regex", Value: "["} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			match := *valid.Match
			match.All = append([]Condition(nil), valid.Match.All...)
			candidate.Match = &match
			test.mutate(&candidate)
			if err := ValidateRule(candidate); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
