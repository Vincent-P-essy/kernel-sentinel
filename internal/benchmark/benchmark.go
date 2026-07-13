package benchmark

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
	"gopkg.in/yaml.v3"
)

type TruthEntry struct {
	ScenarioID    string   `yaml:"scenario_id" json:"scenario_id"`
	Technique     string   `yaml:"technique" json:"technique"`
	Title         string   `yaml:"title" json:"title"`
	ExpectedRules []string `yaml:"expected_rules" json:"expected_rules"`
}

type TechniqueResult struct {
	ScenarioID         string   `json:"scenario_id"`
	Technique          string   `json:"technique"`
	Title              string   `json:"title"`
	Detected           bool     `json:"detected"`
	RuleID             string   `json:"rule_id,omitempty"`
	LatencyNS          int64    `json:"latency_ns,omitempty"`
	EventsUsed         []string `json:"events_used,omitempty"`
	ExpectedRules      []string `json:"expected_rules"`
	Attribution        string   `json:"attribution"`
	CausallyAttributed bool     `json:"causally_attributed"`
}

type Summary struct {
	Techniques       int     `json:"techniques"`
	Detected         int     `json:"detected"`
	Recall           float64 `json:"recall"`
	AttackEvents     int     `json:"attack_events"`
	BenignEvents     int     `json:"benign_events"`
	FalsePositives   int     `json:"false_positives"`
	FalsePositiveK   float64 `json:"false_positives_per_1000_events"`
	P50LatencyNS     int64   `json:"p50_latency_ns"`
	P95LatencyNS     int64   `json:"p95_latency_ns"`
	EvaluationTimeNS int64   `json:"evaluation_time_ns"`
	InputAlerts      int     `json:"input_alerts,omitempty"`
	Attributed       int     `json:"causally_attributed,omitempty"`
	RulePresenceOnly int     `json:"rule_presence_only,omitempty"`
}

type Evaluation struct {
	Mode                    string   `json:"mode"`
	DetectionClaim          string   `json:"detection_claim"`
	AlertsWithoutScenarioID int      `json:"alerts_without_scenario_id,omitempty"`
	Limitations             []string `json:"limitations,omitempty"`
}

type Report struct {
	SchemaVersion string            `json:"schema_version"`
	GeneratedAt   time.Time         `json:"generated_at"`
	Rules         int               `json:"rules"`
	Evaluation    Evaluation        `json:"evaluation"`
	Summary       Summary           `json:"summary"`
	Matrix        []TechniqueResult `json:"matrix"`
	BenignAlerts  []model.Alert     `json:"benign_alerts,omitempty"`
}

func Run(rules []detection.Rule, attackPath, benignPath, truthPath string) (Report, error) {
	started := time.Now()
	truth, err := loadTruth(truthPath)
	if err != nil {
		return Report{}, err
	}
	attackEvents, err := loadEvents(attackPath)
	if err != nil {
		return Report{}, err
	}
	benignEvents, err := loadEvents(benignPath)
	if err != nil {
		return Report{}, err
	}
	attackAlerts := process(rules, attackEvents)
	benignAlerts := process(rules, benignEvents)

	matrix := make([]TechniqueResult, 0, len(truth))
	latencies := make([]int64, 0, len(truth))
	detected := 0
	for _, expected := range truth {
		result := TechniqueResult{
			ScenarioID:    expected.ScenarioID,
			Technique:     expected.Technique,
			Title:         expected.Title,
			ExpectedRules: append([]string(nil), expected.ExpectedRules...),
			Attribution:   "none",
		}
		for _, alert := range attackAlerts {
			if !contains(alert.ScenarioIDs, expected.ScenarioID) || !contains(expected.ExpectedRules, alert.RuleID) {
				continue
			}
			if !result.Detected || alert.DetectionLatency < result.LatencyNS {
				result.Detected = true
				result.RuleID = alert.RuleID
				result.LatencyNS = alert.DetectionLatency
				result.EventsUsed = eventKinds(alert.Evidence)
				result.Attribution = "scenario_id"
				result.CausallyAttributed = true
			}
		}
		if result.Detected {
			detected++
			latencies = append(latencies, result.LatencyNS)
		}
		matrix = append(matrix, result)
	}
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	summary := Summary{
		Techniques:       len(truth),
		Detected:         detected,
		AttackEvents:     len(attackEvents),
		BenignEvents:     len(benignEvents),
		FalsePositives:   len(benignAlerts),
		P50LatencyNS:     percentile(latencies, 0.50),
		P95LatencyNS:     percentile(latencies, 0.95),
		EvaluationTimeNS: time.Since(started).Nanoseconds(),
	}
	if summary.Techniques > 0 {
		summary.Recall = float64(summary.Detected) / float64(summary.Techniques)
	}
	if summary.BenignEvents > 0 {
		summary.FalsePositiveK = float64(summary.FalsePositives) * 1000 / float64(summary.BenignEvents)
	}
	return Report{
		SchemaVersion: "1.1",
		GeneratedAt:   time.Now().UTC(),
		Rules:         len(rules),
		Evaluation: Evaluation{
			Mode:           "deterministic_replay",
			DetectionClaim: "A technique is detected only when an alert matches both its scenario_id and an expected rule_id.",
		},
		Summary:      summary,
		Matrix:       matrix,
		BenignAlerts: benignAlerts,
	}, nil
}

// RunLiveAlerts evaluates alerts emitted by a live collector against the expected
// rules in the lab ground truth. Alerts without scenario_ids can establish only
// that an expected rule fired somewhere in the capture, not that a particular lab
// action caused it.
func RunLiveAlerts(ruleCount int, alertPath, truthPath string) (Report, error) {
	started := time.Now()
	truth, err := loadTruth(truthPath)
	if err != nil {
		return Report{}, err
	}
	alerts, err := loadAlerts(alertPath)
	if err != nil {
		return Report{}, err
	}

	withoutScenarioID := 0
	for _, alert := range alerts {
		if len(alert.ScenarioIDs) == 0 {
			withoutScenarioID++
		}
	}

	matrix := make([]TechniqueResult, 0, len(truth))
	latencies := make([]int64, 0, len(truth))
	detected := 0
	attributed := 0
	presenceOnly := 0
	for _, expected := range truth {
		result := TechniqueResult{
			ScenarioID:    expected.ScenarioID,
			Technique:     expected.Technique,
			Title:         expected.Title,
			ExpectedRules: append([]string(nil), expected.ExpectedRules...),
			Attribution:   "none",
		}

		// Prefer explicit scenario attribution whenever the alert carries it.
		for _, alert := range alerts {
			if !contains(alert.ScenarioIDs, expected.ScenarioID) || !contains(expected.ExpectedRules, alert.RuleID) {
				continue
			}
			applyAlert(&result, alert, "scenario_id")
		}
		// A live kernel event normally has no scenario marker. In that case the
		// report records rule presence, but deliberately does not claim causality.
		if !result.Detected {
			for _, alert := range alerts {
				if len(alert.ScenarioIDs) != 0 || !contains(expected.ExpectedRules, alert.RuleID) {
					continue
				}
				applyAlert(&result, alert, "rule_id_presence")
			}
		}

		if result.Detected {
			detected++
			if result.CausallyAttributed {
				attributed++
			} else {
				presenceOnly++
			}
			if result.LatencyNS > 0 {
				latencies = append(latencies, result.LatencyNS)
			}
		}
		matrix = append(matrix, result)
	}
	sort.Slice(latencies, func(left, right int) bool { return latencies[left] < latencies[right] })
	summary := Summary{
		Techniques:       len(truth),
		Detected:         detected,
		P50LatencyNS:     percentile(latencies, 0.50),
		P95LatencyNS:     percentile(latencies, 0.95),
		EvaluationTimeNS: time.Since(started).Nanoseconds(),
		InputAlerts:      len(alerts),
		Attributed:       attributed,
		RulePresenceOnly: presenceOnly,
	}
	if summary.Techniques > 0 {
		summary.Recall = float64(summary.Detected) / float64(summary.Techniques)
	}
	evaluation := Evaluation{
		Mode:                    "live_alerts",
		DetectionClaim:          "Detected means that an expected rule_id was observed; causal attribution additionally requires the matching scenario_id on the alert.",
		AlertsWithoutScenarioID: withoutScenarioID,
	}
	if withoutScenarioID > 0 {
		evaluation.Limitations = []string{fmt.Sprintf(
			"%d of %d alerts have no scenario_id; rule_id-presence matches do not establish that a specific lab scenario caused the alert.",
			withoutScenarioID,
			len(alerts),
		)}
	}
	return Report{
		SchemaVersion: "1.1",
		GeneratedAt:   time.Now().UTC(),
		Rules:         ruleCount,
		Evaluation:    evaluation,
		Summary:       summary,
		Matrix:        matrix,
	}, nil
}

func applyAlert(result *TechniqueResult, alert model.Alert, attribution string) {
	if result.Detected && result.LatencyNS > 0 && (alert.DetectionLatency <= 0 || alert.DetectionLatency >= result.LatencyNS) {
		return
	}
	result.Detected = true
	result.RuleID = alert.RuleID
	result.LatencyNS = alert.DetectionLatency
	result.EventsUsed = eventKinds(alert.Evidence)
	result.Attribution = attribution
	result.CausallyAttributed = attribution == "scenario_id"
}

func loadTruth(path string) ([]TruthEntry, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read ground truth: %w", err)
	}
	var document struct {
		SchemaVersion string       `yaml:"schema_version"`
		Techniques    []TruthEntry `yaml:"techniques"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(content)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("decode ground truth: %w", err)
	}
	if document.SchemaVersion != "1.0" || len(document.Techniques) == 0 {
		return nil, fmt.Errorf("ground truth must use schema 1.0 and define techniques")
	}
	seen := make(map[string]struct{})
	for _, entry := range document.Techniques {
		if entry.ScenarioID == "" || entry.Technique == "" || len(entry.ExpectedRules) == 0 {
			return nil, fmt.Errorf("incomplete ground truth entry for %q", entry.ScenarioID)
		}
		if _, exists := seen[entry.ScenarioID]; exists {
			return nil, fmt.Errorf("duplicate ground truth scenario %s", entry.ScenarioID)
		}
		seen[entry.ScenarioID] = struct{}{}
	}
	return document.Techniques, nil
}

func loadEvents(path string) ([]model.Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open events %s: %w", path, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	events := make([]model.Event, 0)
	line := 0
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var event model.Event
		if err := json.Unmarshal(scanner.Bytes(), &event); err != nil {
			return nil, fmt.Errorf("decode %s line %d: %w", path, line, err)
		}
		if event.Timestamp.IsZero() {
			return nil, fmt.Errorf("%s line %d has no timestamp", path, line)
		}
		events = append(events, event)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return events, nil
}

func loadAlerts(path string) ([]model.Alert, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open alerts %s: %w", path, err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	alerts := make([]model.Alert, 0)
	line := 0
	for scanner.Scan() {
		line++
		if len(bytes.TrimSpace(scanner.Bytes())) == 0 {
			continue
		}
		var alert model.Alert
		if err := json.Unmarshal(scanner.Bytes(), &alert); err != nil {
			return nil, fmt.Errorf("decode %s line %d: %w", path, line, err)
		}
		if strings.TrimSpace(alert.RuleID) == "" {
			return nil, fmt.Errorf("%s line %d has no rule_id", path, line)
		}
		alerts = append(alerts, alert)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan %s: %w", path, err)
	}
	return alerts, nil
}

func process(rules []detection.Rule, events []model.Event) []model.Alert {
	engine := detection.NewEngine(rules, false)
	alerts := make([]model.Alert, 0)
	for _, event := range events {
		event.ObservedAt = time.Now()
		alerts = append(alerts, engine.Process(event)...)
	}
	return alerts
}

func eventKinds(events []model.Event) []string {
	seen := make(map[string]struct{})
	for _, event := range events {
		seen[string(event.Kind)] = struct{}{}
	}
	result := make([]string, 0, len(seen))
	for kind := range seen {
		result = append(result, kind)
	}
	sort.Strings(result)
	return result
}

func percentile(values []int64, quantile float64) int64 {
	if len(values) == 0 {
		return 0
	}
	index := int(float64(len(values)-1) * quantile)
	return values[index]
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
