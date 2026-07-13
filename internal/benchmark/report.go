package benchmark

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func Write(report Report, outputDirectory string) (map[string]string, error) {
	if err := os.MkdirAll(outputDirectory, 0o755); err != nil {
		return nil, fmt.Errorf("create report directory: %w", err)
	}
	paths := map[string]string{
		"json":     filepath.Join(outputDirectory, "benchmark.json"),
		"csv":      filepath.Join(outputDirectory, "matrix.csv"),
		"markdown": filepath.Join(outputDirectory, "BENCHMARK.md"),
	}
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode benchmark: %w", err)
	}
	if err := os.WriteFile(paths["json"], append(encoded, '\n'), 0o644); err != nil {
		return nil, err
	}
	if err := writeCSV(report, paths["csv"]); err != nil {
		return nil, err
	}
	if err := os.WriteFile(paths["markdown"], []byte(markdown(report)), 0o644); err != nil {
		return nil, err
	}
	return paths, nil
}

func writeCSV(report Report, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	if err := writer.Write([]string{"scenario_id", "technique", "title", "detected", "rule_id", "latency_ns", "events_used", "attribution", "causally_attributed"}); err != nil {
		return err
	}
	for _, item := range report.Matrix {
		if err := writer.Write([]string{
			item.ScenarioID,
			item.Technique,
			item.Title,
			strconv.FormatBool(item.Detected),
			item.RuleID,
			strconv.FormatInt(item.LatencyNS, 10),
			strings.Join(item.EventsUsed, " + "),
			item.Attribution,
			strconv.FormatBool(item.CausallyAttributed),
		}); err != nil {
			return err
		}
	}
	return writer.Error()
}

func markdown(report Report) string {
	var builder strings.Builder
	builder.WriteString("# Kernel Sentinel - reproducible detection benchmark\n\n")
	if report.Evaluation.Mode == "live_alerts" {
		fmt.Fprintf(
			&builder,
			"Mode: `live alerts` | Rules: `%d` | Alerts read: `%d` | Expected rule-ID coverage: `%.1f%%` | Causally attributed: `%d` | Rule presence only: `%d`\n\n",
			report.Rules,
			report.Summary.InputAlerts,
			report.Summary.Recall*100,
			report.Summary.Attributed,
			report.Summary.RulePresenceOnly,
		)
		builder.WriteString("## Evaluation scope\n\n")
		builder.WriteString(report.Evaluation.DetectionClaim + "\n\n")
		for _, limitation := range report.Evaluation.Limitations {
			fmt.Fprintf(&builder, "- Limitation: %s\n", limitation)
		}
		if len(report.Evaluation.Limitations) > 0 {
			builder.WriteString("\n")
		}
	} else {
		fmt.Fprintf(&builder, "Rules: `%d` | Techniques: `%d` | Recall: `%.1f%%` | Benign false positives: `%d`\n\n", report.Rules, report.Summary.Techniques, report.Summary.Recall*100, report.Summary.FalsePositives)
	}
	builder.WriteString("| MITRE technique | Scenario | Detected | Latency | Events used | Rule | Attribution |\n")
	builder.WriteString("|---|---|---:|---:|---|---|---|\n")
	for _, item := range report.Matrix {
		detected := "No"
		if item.Detected {
			detected = "Yes"
		}
		fmt.Fprintf(
			&builder,
			"| %s | %s | %s | %s | %s | `%s` | %s |\n",
			item.Technique,
			item.Title,
			detected,
			time.Duration(item.LatencyNS),
			strings.Join(item.EventsUsed, " + "),
			item.RuleID,
			attributionLabel(item.Attribution),
		)
	}
	if report.Evaluation.Mode == "live_alerts" {
		builder.WriteString("\nLatency is copied from each emitted alert and measures event ingestion to the completed decision. A blank/zero value means that no positive latency was recorded. It does not measure or prove scenario-to-alert causality.\n")
	} else {
		builder.WriteString("\nLatency is measured from in-process ingestion to the completed decision on the deterministic replay. It does not include kernel-to-user ring-buffer transport.\n")
	}
	return builder.String()
}

func attributionLabel(attribution string) string {
	switch attribution {
	case "scenario_id":
		return "scenario_id + rule_id"
	case "rule_id_presence":
		return "rule_id presence only"
	default:
		return "none"
	}
}
