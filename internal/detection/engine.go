package detection

import (
	"crypto/sha256"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
)

type sequenceState struct {
	nextIndex int
	startedAt time.Time
	events    []model.Event
}

type Engine struct {
	mu              sync.Mutex
	rules           []Rule
	states          map[string]map[string][]sequenceState
	scorer          *BehaviorScorer
	now             func() time.Time
	processedEvents uint64
}

func NewEngine(rules []Rule, behavioral bool) *Engine {
	engine := &Engine{
		rules:  append([]Rule(nil), rules...),
		states: make(map[string]map[string][]sequenceState),
		now:    time.Now,
	}
	if behavioral {
		engine.scorer = NewBehaviorScorer(60, 2*time.Minute, 30*time.Second)
	}
	return engine
}

func (engine *Engine) Rules() []Rule {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return append([]Rule(nil), engine.rules...)
}

func (engine *Engine) Process(event model.Event) []model.Alert {
	engine.mu.Lock()
	defer engine.mu.Unlock()

	event.EnsureDefaults(engine.now())
	engine.processedEvents++
	if engine.processedEvents%1024 == 0 {
		engine.prune(event.Timestamp)
	}
	alerts := make([]model.Alert, 0)
	for _, rule := range engine.rules {
		if rule.Match != nil {
			if Matches(event, *rule.Match) {
				alerts = append(alerts, buildAlert(rule, []model.Event{event}, entityFor(rule, event), engine.now()))
			}
			continue
		}
		alerts = append(alerts, engine.processSequence(rule, event)...)
	}
	if engine.scorer != nil {
		if alert := engine.scorer.Process(event, engine.now()); alert != nil {
			alerts = append(alerts, *alert)
		}
	}
	return alerts
}

func (engine *Engine) prune(now time.Time) {
	if now.IsZero() {
		return
	}
	windows := make(map[string]time.Duration, len(engine.rules))
	for _, rule := range engine.rules {
		if len(rule.Sequence) > 0 {
			windows[rule.ID] = rule.Within.Duration
		}
	}
	for ruleID, entities := range engine.states {
		window := windows[ruleID]
		for entity, states := range entities {
			retained := states[:0]
			for _, state := range states {
				if !now.Before(state.startedAt) && now.Sub(state.startedAt) > window {
					continue
				}
				retained = append(retained, state)
			}
			if len(retained) == 0 {
				delete(entities, entity)
			} else {
				entities[entity] = retained
			}
		}
		if len(entities) == 0 {
			delete(engine.states, ruleID)
		}
	}
	if engine.scorer != nil {
		engine.scorer.Prune(now)
	}
}

func (engine *Engine) processSequence(rule Rule, event model.Event) []model.Alert {
	entity := entityFor(rule, event)
	if rule.GroupBy != "" && entity == "" {
		return nil
	}
	if entity == "" {
		entity = "global"
	}
	byEntity, ok := engine.states[rule.ID]
	if !ok {
		byEntity = make(map[string][]sequenceState)
		engine.states[rule.ID] = byEntity
	}

	active := byEntity[entity]
	next := make([]sequenceState, 0, len(active)+1)
	alerts := make([]model.Alert, 0, 1)
	for _, state := range active {
		if event.Timestamp.Sub(state.startedAt) > rule.Within.Duration {
			continue
		}
		if state.nextIndex < len(rule.Sequence) && Matches(event, rule.Sequence[state.nextIndex].Match) {
			state.events = append(state.events, event)
			state.nextIndex++
			if state.nextIndex == len(rule.Sequence) {
				alerts = append(alerts, buildAlert(rule, state.events, entity, engine.now()))
				continue
			}
		}
		next = append(next, state)
	}
	if Matches(event, rule.Sequence[0].Match) {
		next = append(next, sequenceState{
			nextIndex: 1,
			startedAt: event.Timestamp,
			events:    []model.Event{event},
		})
	}
	if len(next) == 0 {
		delete(byEntity, entity)
	} else {
		byEntity[entity] = next
	}
	return alerts
}

func entityFor(rule Rule, event model.Event) string {
	if rule.GroupBy != "" {
		return model.FieldString(event, rule.GroupBy)
	}
	if event.Container.ID != "" {
		return "container:" + event.Container.ID
	}
	return fmt.Sprintf("process:%d", event.Process.PID)
}

func buildAlert(rule Rule, evidence []model.Event, entity string, now time.Time) model.Alert {
	eventIDs := make([]string, 0, len(evidence))
	scenarios := make(map[string]struct{})
	first := evidence[0].Timestamp
	lastObserved := evidence[0].ObservedAt
	for _, event := range evidence {
		eventIDs = append(eventIDs, event.ID)
		if event.Timestamp.Before(first) {
			first = event.Timestamp
		}
		if event.ObservedAt.After(lastObserved) {
			lastObserved = event.ObservedAt
		}
		if event.ScenarioID != "" {
			scenarios[event.ScenarioID] = struct{}{}
		}
	}
	scenarioIDs := make([]string, 0, len(scenarios))
	for scenario := range scenarios {
		scenarioIDs = append(scenarioIDs, scenario)
	}
	sort.Strings(scenarioIDs)
	digest := sha256.Sum256([]byte(rule.ID + "\x00" + strings.Join(eventIDs, "\x00")))
	latency := now.Sub(lastObserved)
	if latency < 0 {
		latency = 0
	}
	return model.Alert{
		SchemaVersion:    "1.0",
		ID:               fmt.Sprintf("%x", digest[:12]),
		RuleID:           rule.ID,
		Title:            rule.Title,
		Description:      rule.Description,
		Severity:         rule.Severity,
		Score:            rule.Score,
		MITRE:            append([]string(nil), rule.MITRE...),
		Tags:             append([]string(nil), rule.Tags...),
		DetectedAt:       now,
		FirstEventAt:     first,
		DetectionLatency: latency.Nanoseconds(),
		Entity:           entity,
		EventIDs:         eventIDs,
		ScenarioIDs:      scenarioIDs,
		Evidence:         append([]model.Event(nil), evidence...),
	}
}
