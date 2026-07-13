package detection

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

var ruleIDPattern = regexp.MustCompile(`^KS-[A-Z0-9-]+$`)

func LoadRules(path string) ([]Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat rules path: %w", err)
	}
	paths := []string{path}
	if info.IsDir() {
		paths = paths[:0]
		err = filepath.WalkDir(path, func(current string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if !entry.IsDir() && (strings.HasSuffix(entry.Name(), ".yaml") || strings.HasSuffix(entry.Name(), ".yml")) {
				paths = append(paths, current)
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("walk rules: %w", err)
		}
	}
	sort.Strings(paths)

	rules := make([]Rule, 0)
	seen := make(map[string]string)
	for _, file := range paths {
		content, readErr := os.ReadFile(file)
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", file, readErr)
		}
		var document struct {
			Rules []Rule `yaml:"rules"`
		}
		decoder := yaml.NewDecoder(strings.NewReader(string(content)))
		decoder.KnownFields(true)
		if decodeErr := decoder.Decode(&document); decodeErr != nil {
			return nil, fmt.Errorf("decode %s: %w", file, decodeErr)
		}
		for index := range document.Rules {
			rule := document.Rules[index]
			if validationErr := ValidateRule(rule); validationErr != nil {
				return nil, fmt.Errorf("%s rule %d: %w", file, index+1, validationErr)
			}
			if previous, exists := seen[rule.ID]; exists {
				return nil, fmt.Errorf("duplicate rule id %s in %s and %s", rule.ID, previous, file)
			}
			seen[rule.ID] = file
			if rule.IsEnabled() {
				rules = append(rules, rule)
			}
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no enabled detection rules found in %s", path)
	}
	return rules, nil
}

func ValidateRule(rule Rule) error {
	if !ruleIDPattern.MatchString(rule.ID) {
		return fmt.Errorf("id %q must match %s", rule.ID, ruleIDPattern)
	}
	if strings.TrimSpace(rule.Title) == "" || strings.TrimSpace(rule.Description) == "" {
		return fmt.Errorf("title and description are required")
	}
	if rule.Score < 1 || rule.Score > 100 {
		return fmt.Errorf("score must be between 1 and 100")
	}
	switch rule.Severity {
	case "low", "medium", "high", "critical":
	default:
		return fmt.Errorf("unsupported severity %q", rule.Severity)
	}
	if len(rule.MITRE) == 0 {
		return fmt.Errorf("at least one MITRE technique is required")
	}
	if (rule.Match == nil) == (len(rule.Sequence) == 0) {
		return fmt.Errorf("define exactly one match block or sequence")
	}
	if rule.Match != nil {
		if err := validateMatch(*rule.Match); err != nil {
			return err
		}
	}
	if len(rule.Sequence) > 0 {
		if len(rule.Sequence) < 2 {
			return fmt.Errorf("a sequence requires at least two steps")
		}
		if rule.Within.Duration <= 0 {
			return fmt.Errorf("a sequence requires a positive within duration")
		}
		for _, step := range rule.Sequence {
			if strings.TrimSpace(step.Name) == "" {
				return fmt.Errorf("sequence step name is required")
			}
			if err := validateMatch(step.Match); err != nil {
				return fmt.Errorf("step %s: %w", step.Name, err)
			}
		}
	}
	return nil
}

func validateMatch(block MatchBlock) error {
	if len(block.All) == 0 && len(block.Any) == 0 {
		return fmt.Errorf("match block needs all or any conditions")
	}
	for _, condition := range append(append([]Condition{}, block.All...), block.Any...) {
		if strings.TrimSpace(condition.Field) == "" {
			return fmt.Errorf("condition field is required")
		}
		switch condition.Op {
		case "eq", "neq", "contains", "prefix", "suffix", "regex", "in", "gt", "gte", "lt", "lte", "exists":
		default:
			return fmt.Errorf("unsupported operator %q", condition.Op)
		}
		if condition.Op == "regex" {
			if _, err := regexp.Compile(fmt.Sprint(condition.Value)); err != nil {
				return fmt.Errorf("invalid regex for %s: %w", condition.Field, err)
			}
		}
	}
	return nil
}
