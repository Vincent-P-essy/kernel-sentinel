package detection

import (
	"fmt"
	"math"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

type behaviorProfile struct {
	score       float64
	updatedAt   time.Time
	lastAlertAt time.Time
}

type BehaviorScorer struct {
	threshold float64
	halfLife  time.Duration
	cooldown  time.Duration
	profiles  map[string]behaviorProfile
}

func NewBehaviorScorer(threshold float64, halfLife, cooldown time.Duration) *BehaviorScorer {
	return &BehaviorScorer{
		threshold: threshold,
		halfLife:  halfLife,
		cooldown:  cooldown,
		profiles:  make(map[string]behaviorProfile),
	}
}

func (scorer *BehaviorScorer) Prune(now time.Time) {
	maximumIdle := 10 * scorer.halfLife
	for entity, profile := range scorer.profiles {
		if !now.Before(profile.updatedAt) && now.Sub(profile.updatedAt) > maximumIdle {
			delete(scorer.profiles, entity)
		}
	}
}

func (scorer *BehaviorScorer) Process(event model.Event, now time.Time) *model.Alert {
	entity := fmt.Sprintf("process:%d", event.Process.PID)
	if event.Container.ID != "" {
		entity = "container:" + event.Container.ID
	}
	profile := scorer.profiles[entity]
	if !profile.updatedAt.IsZero() {
		elapsed := event.Timestamp.Sub(profile.updatedAt)
		if elapsed > 0 {
			profile.score *= math.Pow(0.5, elapsed.Seconds()/scorer.halfLife.Seconds())
		}
	}
	weight, features := behaviorWeight(event)
	profile.score = math.Min(100, profile.score+weight)
	profile.updatedAt = event.Timestamp
	scorer.profiles[entity] = profile

	if profile.score < scorer.threshold || (!profile.lastAlertAt.IsZero() && now.Sub(profile.lastAlertAt) < scorer.cooldown) {
		return nil
	}
	profile.lastAlertAt = now
	scorer.profiles[entity] = profile
	rule := Rule{
		ID:          "KS-BEHAVIOR-001",
		Title:       "High-risk behavioral activity",
		Description: "Multiple independently suspicious runtime signals crossed the behavioral threshold.",
		Severity:    "high",
		Score:       int(math.Round(profile.score)),
		MITRE:       []string{"TA0002", "TA0004"},
		Tags:        append([]string{"behavioral"}, features...),
	}
	return pointer(buildAlert(rule, []model.Event{event}, entity, now))
}

func behaviorWeight(event model.Event) (float64, []string) {
	weight := 0.0
	features := make([]string, 0, 5)
	if event.Kind == model.EventExec && isTemporaryPath(event.Process.Executable) {
		weight += 30
		features = append(features, "temporary-executable")
	}
	if event.File != nil && isSensitivePath(event.File.Path) {
		weight += 35
		features = append(features, "sensitive-file")
	}
	if event.Network != nil && isExternalAddress(event.Network.Address) {
		weight += 20
		features = append(features, "external-network")
	}
	if event.Kind == model.EventSetUID && event.Privilege != nil && event.Privilege.TargetUID == 0 {
		weight += 40
		features = append(features, "privilege-elevation")
	}
	if event.Container.ID != "" {
		weight += 5
		features = append(features, "container")
	}
	if !event.Outcome.Success {
		weight += 5
		features = append(features, "failed-syscall")
	}
	return weight, features
}

func isTemporaryPath(path string) bool {
	cleaned := filepath.Clean(path)
	return strings.HasPrefix(cleaned, "/tmp/") || strings.HasPrefix(cleaned, "/var/tmp/") || strings.HasPrefix(cleaned, "/dev/shm/")
}

func isSensitivePath(path string) bool {
	cleaned := filepath.Clean(path)
	return cleaned == "/etc/shadow" || cleaned == "/var/run/docker.sock" ||
		strings.Contains(cleaned, "/.ssh/") || strings.Contains(cleaned, "/var/run/secrets/kubernetes.io/")
}

func isExternalAddress(address string) bool {
	ip := net.ParseIP(address)
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback() && !ip.IsUnspecified()
}

func pointer[T any](value T) *T {
	return &value
}
