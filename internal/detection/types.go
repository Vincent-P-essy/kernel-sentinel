package detection

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

type Duration struct {
	time.Duration
}

func (duration *Duration) UnmarshalYAML(node *yaml.Node) error {
	parsed, err := time.ParseDuration(node.Value)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", node.Value, err)
	}
	if parsed <= 0 {
		return fmt.Errorf("duration must be positive")
	}
	duration.Duration = parsed
	return nil
}

type Condition struct {
	Field string      `yaml:"field" json:"field"`
	Op    string      `yaml:"op" json:"op"`
	Value interface{} `yaml:"value" json:"value"`
}

type MatchBlock struct {
	All []Condition `yaml:"all,omitempty" json:"all,omitempty"`
	Any []Condition `yaml:"any,omitempty" json:"any,omitempty"`
}

type SequenceStep struct {
	Name  string     `yaml:"name" json:"name"`
	Match MatchBlock `yaml:"match" json:"match"`
}

type Rule struct {
	ID          string         `yaml:"id" json:"id"`
	Title       string         `yaml:"title" json:"title"`
	Description string         `yaml:"description" json:"description"`
	Severity    string         `yaml:"severity" json:"severity"`
	Score       int            `yaml:"score" json:"score"`
	MITRE       []string       `yaml:"mitre" json:"mitre"`
	Tags        []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
	Match       *MatchBlock    `yaml:"match,omitempty" json:"match,omitempty"`
	Sequence    []SequenceStep `yaml:"sequence,omitempty" json:"sequence,omitempty"`
	Within      Duration       `yaml:"within,omitempty" json:"within,omitempty"`
	GroupBy     string         `yaml:"group_by,omitempty" json:"group_by,omitempty"`
	Enabled     *bool          `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

func (rule Rule) IsEnabled() bool {
	return rule.Enabled == nil || *rule.Enabled
}
