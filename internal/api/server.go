package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Vincent-P-essy/kernel-sentinel/internal/detection"
	"github.com/Vincent-P-essy/kernel-sentinel/internal/store"
)

//go:embed web/*
var webAssets embed.FS

type Server struct {
	address     string
	store       *store.Store
	rules       []detection.Rule
	logger      *slog.Logger
	http        *http.Server
	streamSlots chan struct{}
}

func NewServer(address string, eventStore *store.Store, rules []detection.Rule, logger *slog.Logger) *Server {
	server := &Server{
		address:     address,
		store:       eventStore,
		rules:       rules,
		logger:      logger,
		streamSlots: make(chan struct{}, 32),
	}
	server.http = &http.Server{
		Addr:              address,
		Handler:           server.routes(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	return server
}

func (server *Server) Run(ctx context.Context) error {
	result := make(chan error, 1)
	go func() {
		server.logger.Info("alert API listening", "address", server.address)
		result <- server.http.ListenAndServe()
	}()
	select {
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.http.Shutdown(shutdownContext); err != nil {
			return fmt.Errorf("shutdown API: %w", err)
		}
		return nil
	case err := <-result:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func (server *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("GET /api/v1/stats", server.stats)
	mux.HandleFunc("GET /api/v1/events", server.events)
	mux.HandleFunc("GET /api/v1/alerts", server.alerts)
	mux.HandleFunc("GET /api/v1/rules", server.ruleList)
	mux.HandleFunc("GET /api/v1/stream", server.stream)
	mux.HandleFunc("GET /metrics", server.metrics)
	assets, err := fs.Sub(webAssets, "web")
	if err == nil {
		mux.Handle("GET /", http.FileServer(http.FS(assets)))
	}
	return securityHeaders(mux)
}

func (server *Server) health(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]interface{}{
		"status": "ok",
		"source": server.store.Stats().SourceStatus,
	})
}

func (server *Server) stats(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, server.store.Stats())
}

func (server *Server) events(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, server.store.RecentEvents(parseLimit(request, 100)))
}

func (server *Server) alerts(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, server.store.RecentAlerts(parseLimit(request, 100)))
}

func (server *Server) ruleList(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, server.rules)
}

func (server *Server) metrics(response http.ResponseWriter, _ *http.Request) {
	response.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write([]byte(server.store.Prometheus()))
}

func (server *Server) stream(response http.ResponseWriter, request *http.Request) {
	flusher, ok := response.(http.Flusher)
	if !ok {
		http.Error(response, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	if server.streamSlots != nil {
		select {
		case server.streamSlots <- struct{}{}:
			defer func() { <-server.streamSlots }()
		default:
			http.Error(response, "stream capacity reached", http.StatusTooManyRequests)
			return
		}
	}
	response.Header().Set("Content-Type", "text/event-stream")
	response.Header().Set("Cache-Control", "no-cache")
	response.Header().Set("X-Accel-Buffering", "no")
	alerts, unsubscribe := server.store.Subscribe(32)
	defer unsubscribe()
	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()
	for {
		select {
		case <-request.Context().Done():
			return
		case alert, ok := <-alerts:
			if !ok {
				return
			}
			payload, _ := json.Marshal(alert)
			fmt.Fprintf(response, "event: alert\ndata: %s\n\n", payload)
			flusher.Flush()
		case <-keepalive.C:
			_, _ = fmt.Fprint(response, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func parseLimit(request *http.Request, fallback int) int {
	value, err := strconv.Atoi(request.URL.Query().Get("limit"))
	if err != nil || value < 1 {
		return fallback
	}
	if value > 500 {
		return 500
	}
	return value
}

func writeJSON(response http.ResponseWriter, status int, value interface{}) {
	response.Header().Set("Content-Type", "application/json; charset=utf-8")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		response.Header().Set("X-Content-Type-Options", "nosniff")
		response.Header().Set("Referrer-Policy", "no-referrer")
		response.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if request.URL.Path == "/healthz" || request.URL.Path == "/metrics" || len(request.URL.Path) >= 8 && request.URL.Path[:8] == "/api/v1/" {
			response.Header().Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(response, request)
	})
}
