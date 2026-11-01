package family

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestQuietExecShowsOutputOnFailureOnly(t *testing.T) {
	var ok, bad bytes.Buffer
	if _, err := (QuietExec{Stderr: &ok}).Run(context.Background(), nil, "sh", "-c", "echo noise >&2; exit 0"); err != nil {
		t.Fatal(err)
	}
	if ok.String() != "" {
		t.Errorf("shown on success: %q", ok.String())
	}
	if _, err := (QuietExec{Stderr: &bad}).Run(context.Background(), nil, "sh", "-c", "echo noise >&2; exit 3"); err == nil {
		t.Fatal("no error")
	}
	if bad.String() != "noise\n" {
		t.Errorf("on failure: %q", bad.String())
	}
	var v bytes.Buffer
	if _, err := (QuietExec{Verbose: true, Stderr: &v}).Run(context.Background(), nil, "sh", "-c", "echo noise >&2; exit 0"); err != nil {
		t.Fatal(err)
	}
	if v.String() != "noise\n" {
		t.Errorf("verbose: %q", v.String())
	}
}

func TestUpStepLines(t *testing.T) {
	w := newWS(t, yamlConf(""))
	out, err := w.up("y\n", newFake())
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{"hub image verified\n", "lock crm-prod: image verified\n", "lock events: image verified\n", "lock crm-prod: started\n", "lock events: started\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "Verification for") {
		t.Errorf("cosign output leaked:\n%s", out)
	}
}
