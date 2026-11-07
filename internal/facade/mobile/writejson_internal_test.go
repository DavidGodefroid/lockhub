package mobile

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

// writeJSON does not HTML-escape: a signed payload or a ticket the
// phone hashes keeps its <, > and & (#147).
func TestWriteJSONKeepsRawBytes(t *testing.T) {
	rec := httptest.NewRecorder()
	writeJSON(rec, 200, struct {
		Record json.RawMessage `json:"record"`
		Ticket string          `json:"ticket"`
	}{json.RawMessage(`{"a":"x < y & z > w"}`), `{"q":"id <> 2"}`})
	want := `{"record":{"a":"x < y & z > w"},"ticket":"{\"q\":\"id <> 2\"}"}` + "\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("writeJSON wrote\n%s\nwant\n%s", got, want)
	}
}
