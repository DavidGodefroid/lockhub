package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/hub"
)

func TestHello(t *testing.T) {
	srv := httptest.NewServer(Handler("1.2.3"))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/hello")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
	var h Hello
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatal(err)
	}
	if h.Name != "lockhub" || h.Version != "1.2.3" || h.API != Version || h.TicketVersions != nil || h.HubKeyID != "" {
		t.Errorf("hello = %+v", h)
	}
}

func TestUnknownRouteAndMethod(t *testing.T) {
	srv := httptest.NewServer(Handler("dev"))
	defer srv.Close()
	for _, c := range []struct {
		method, path string
		want         int
	}{
		{"GET", "/v1/nope", http.StatusNotFound},
		{"POST", "/v1/hello", http.StatusMethodNotAllowed},
	} {
		req, _ := http.NewRequest(c.method, srv.URL+c.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != c.want {
			t.Errorf("%s %s: status %d, want %d", c.method, c.path, resp.StatusCode, c.want)
		}
	}
}

// A ticket of a lock no longer declared is gone (410 lock_removed), not
// an authentication failure: 401 stays for the signed lock API.
func TestLockRemovedIs410(t *testing.T) {
	rec := httptest.NewRecorder()
	fail(rec, fmt.Errorf("decide: %w", hub.ErrLockRemoved))
	var e Error
	if err := json.Unmarshal(rec.Body.Bytes(), &e); rec.Code != http.StatusGone || err != nil || e.Error != "lock_removed" {
		t.Errorf("fail(ErrLockRemoved) = %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	fail(rec, hub.ErrUnknownLock)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("fail(ErrUnknownLock) = %d", rec.Code)
	}
}
