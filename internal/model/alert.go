package model

import "time"

type Alert struct {
	SchemaVersion    string    `json:"schema_version"`
	ID               string    `json:"id"`
	RuleID           string    `json:"rule_id"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	Severity         string    `json:"severity"`
	Score            int       `json:"score"`
	MITRE            []string  `json:"mitre"`
	Tags             []string  `json:"tags,omitempty"`
	DetectedAt       time.Time `json:"detected_at"`
	FirstEventAt     time.Time `json:"first_event_at"`
	DetectionLatency int64     `json:"detection_latency_ns"`
	Entity           string    `json:"entity"`
	EventIDs         []string  `json:"event_ids"`
	ScenarioIDs      []string  `json:"scenario_ids,omitempty"`
	Evidence         []Event   `json:"evidence"`
}
