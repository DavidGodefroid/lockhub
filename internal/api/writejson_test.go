package api

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// A signed payload (json.RawMessage) leaves writeJSON byte for byte:
// encoding/json's HTML escaping would rewrite its <, > and & and put it
// out of its canonical form (#147). Strings keep their characters too.
func TestWriteJSONKeepsRawBytes(t *testing.T) {
	raw := json.RawMessage(`{"q":"id < 2 AND s <> 'x' AND f & 1 >= 0 -- é"}`)
	rec := httptest.NewRecorder()
	writeJSON(rec, 200, struct {
		Ticket json.RawMessage `json:"ticket"`
		Note   string          `json:"note"`
	}{raw, "a < b & c > d"})
	want := `{"ticket":{"q":"id < 2 AND s <> 'x' AND f & 1 >= 0 -- é"},"note":"a < b & c > d"}` + "\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("writeJSON wrote\n%s\nwant\n%s", got, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content type %q", ct)
	}
}
