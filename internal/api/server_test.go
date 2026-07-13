package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/model"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/store"
)

func TestAPIExposesSanitizedRuntimeState(t *testing.T) {
	eventStore := store.New(10, 10)
	eventStore.SetSourceStatus("complete")
	eventStore.AddEvent(model.Event{ID: "event-1", Kind: model.EventExec})
	eventStore.AddAlerts(model.Alert{ID: "alert-1", RuleID: "KS-TEST-001", Severity: "high", DetectionLatency: int64(time.Millisecond)})
	rules := []detection.Rule{{ID: "KS-TEST-001", Title: "test", Description: "test", Severity: "high", Score: 80, MITRE: []string{"T1000"}}}
	server := &Server{store: eventStore, rules: rules, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	testServer := httptest.NewServer(server.routes())
	defer testServer.Close()

	tests := map[string]string{
		"/healthz":       `"status":"ok"`,
		"/api/v1/stats":  `"event_count":1`,
		"/api/v1/events": `"event-1"`,
		"/api/v1/alerts": `"alert-1"`,
		"/api/v1/rules":  `"KS-TEST-001"`,
		"/metrics":       "kernel_sentinel_events_total",
		"/":              "Kernel Sentinel",
	}
	for path, expected := range tests {
		t.Run(path, func(t *testing.T) {
			response, err := http.Get(testServer.URL + path)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.StatusCode != http.StatusOK || !strings.Contains(string(body), expected) {
				t.Fatalf("%s: status=%d body=%s", path, response.StatusCode, body)
			}
			if response.Header.Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("security headers missing")
			}
		})
	}
}

func TestDashboardHasNoThirdPartyRuntimeDependency(t *testing.T) {
	server := &Server{store: store.New(1, 1), logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	testServer := httptest.NewServer(server.routes())
	defer testServer.Close()
	response, err := http.Get(testServer.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if strings.Contains(string(body), "https://") || strings.Contains(string(body), "http://") {
		t.Fatalf("dashboard references an external runtime dependency: %s", body)
	}
	if !strings.Contains(string(body), "ring-failures") || !strings.Contains(string(body), "process.fork") {
		t.Fatalf("dashboard omits probe health or fork telemetry: %s", body)
	}
	if policy := response.Header.Get("Content-Security-Policy"); strings.Contains(policy, "unpkg.com") {
		t.Fatalf("content security policy allows a third party: %s", policy)
	}
}

func TestServerStartsAndShutsDownWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server := NewServer("127.0.0.1:0", store.New(1, 1), nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := server.Run(ctx); err != nil {
		t.Fatal(err)
	}
}

type responseWithoutFlusher struct {
	header http.Header
	status int
}

func (response *responseWithoutFlusher) Header() http.Header             { return response.header }
func (response *responseWithoutFlusher) Write(value []byte) (int, error) { return len(value), nil }
func (response *responseWithoutFlusher) WriteHeader(status int)          { response.status = status }

func TestStreamRequiresFlusher(t *testing.T) {
	server := &Server{store: store.New(1, 1)}
	response := &responseWithoutFlusher{header: make(http.Header)}
	server.stream(response, httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil))
	if response.status != http.StatusInternalServerError {
		t.Fatalf("status = %d", response.status)
	}
}

func TestStreamCapacityIsBounded(t *testing.T) {
	server := &Server{store: store.New(1, 1), streamSlots: make(chan struct{}, 1)}
	server.streamSlots <- struct{}{}
	response := httptest.NewRecorder()
	server.stream(response, httptest.NewRequest(http.MethodGet, "/api/v1/stream", nil))
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestLimitParsing(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/?limit=900", nil)
	if limit := parseLimit(request, 10); limit != 500 {
		t.Fatalf("limit = %d", limit)
	}
	request = httptest.NewRequest(http.MethodGet, "/?limit=bad", nil)
	if limit := parseLimit(request, 10); limit != 10 {
		t.Fatalf("fallback = %d", limit)
	}
}
