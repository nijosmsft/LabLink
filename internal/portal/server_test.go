package portal

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/nijosmsft/lablink/internal/ops"
)

func TestServerRequiresKey(t *testing.T) {
	reg := ops.NewRegistry(10)
	s, err := New(reg, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Shutdown(context.Background())

	resp, err := http.Get("http://" + s.Addr() + "/")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}

	resp2, err := http.Get(s.URL())
	if err != nil {
		t.Fatalf("get url: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 with key, got %d", resp2.StatusCode)
	}
	body, _ := io.ReadAll(resp2.Body)
	if !strings.Contains(string(body), "LabLink operations") {
		t.Fatalf("unexpected body: %s", body)
	}
}

func TestCancelEndpoint(t *testing.T) {
	reg := ops.NewRegistry(10)
	s, err := New(reg, "127.0.0.1:0")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer s.Shutdown(context.Background())

	ctx, h := reg.Begin(context.Background(), "execute_command", "n", "sleep", nil)

	u, _ := url.Parse(s.URL())
	q := u.Query()
	resp, err := http.Post("http://"+s.Addr()+"/api/ops/cancel?id="+h.ID()+"&k="+q.Get("k"), "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", resp.StatusCode)
	}
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatalf("ctx not cancelled")
	}
	h.Done(ctx.Err())
}

func TestRefusesNonLoopbackBind(t *testing.T) {
	reg := ops.NewRegistry(10)
	if _, err := New(reg, "0.0.0.0:0"); err == nil {
		t.Fatalf("expected error binding 0.0.0.0")
	}
}
