// Package portal exposes a small local HTTP UI listing in-flight LabLink
// operations and offering a Cancel button. It binds to 127.0.0.1 only and
// requires a per-process key (issued at startup) on every request.
package portal

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/nijosmsft/lablink/internal/ops"
)

// Server is a per-process portal.
type Server struct {
	reg     *ops.Registry
	key     string
	addr    string
	httpSrv *http.Server
}

// New constructs a Server bound to a random 127.0.0.1 port. listenAddr may be
// "" (default 127.0.0.1:0) or a fixed value like "127.0.0.1:9092".
func New(reg *ops.Registry, listenAddr string) (*Server, error) {
	if reg == nil {
		return nil, errors.New("portal: nil registry")
	}
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	if !strings.HasPrefix(listenAddr, "127.0.0.1:") && !strings.HasPrefix(listenAddr, "localhost:") {
		return nil, fmt.Errorf("portal: refusing to bind non-loopback address %q", listenAddr)
	}
	key, err := newKey()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("portal: listen: %w", err)
	}
	s := &Server{
		reg:  reg,
		key:  key,
		addr: ln.Addr().String(),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/api/ops", s.handleList)
	mux.HandleFunc("/api/ops/cancel", s.handleCancel)
	mux.HandleFunc("/api/ops/stream", s.handleStream)
	s.httpSrv = &http.Server{
		Handler:           s.requireKey(mux),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = s.httpSrv.Serve(ln)
	}()
	return s, nil
}

// URL returns the bookmarkable URL with the access key embedded.
func (s *Server) URL() string {
	return fmt.Sprintf("http://%s/?k=%s", s.addr, s.key)
}

// Addr returns the bind address.
func (s *Server) Addr() string { return s.addr }

// Shutdown stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil || s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

func (s *Server) requireKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Loopback enforcement: defense in depth.
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || !isLoopback(host) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		k := r.URL.Query().Get("k")
		if k == "" {
			if c, err := r.Cookie("lablink_portal"); err == nil {
				k = c.Value
			}
		}
		if subtle.ConstantTimeCompare([]byte(k), []byte(s.key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		// Refresh cookie so subsequent same-origin XHRs don't need ?k=.
		http.SetCookie(w, &http.Cookie{
			Name:     "lablink_portal",
			Value:    s.key,
			Path:     "/",
			HttpOnly: true,
			SameSite: http.SameSiteStrictMode,
		})
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ops": s.reg.List()})
}

func (s *Server) handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := r.URL.Query().Get("id")
	if id == "" {
		http.Error(w, "missing id", http.StatusBadRequest)
		return
	}
	if !s.reg.Cancel(id) {
		http.Error(w, "unknown or already finished", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	ch, cancel := s.reg.Subscribe()
	defer cancel()

	// Send a snapshot first so a fresh tab paints immediately.
	snap, _ := json.Marshal(map[string]any{"kind": "snapshot", "ops": s.reg.List()})
	fmt.Fprintf(w, "data: %s\n\n", snap)
	flusher.Flush()

	keepalive := time.NewTicker(15 * time.Second)
	defer keepalive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", b)
			flusher.Flush()
		case <-keepalive.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

func newKey() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost"
	}
	return ip.IsLoopback()
}
