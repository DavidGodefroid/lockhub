//go:build lockfamily_managed_test

package main

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/DavidGodefroid/lockkit/managed"
)

var updateManaged = flag.Bool("update-managed", false, "rewrite the goldens of testdata/managed")

func setManaged(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, managed.FileName)
	if body != "" {
		os.WriteFile(p, []byte(body), 0o644)
	}
	managed.SetTestPath(p)
	t.Cleanup(func() { managed.SetTestPath("") })
	return dir
}

// fixedPath replaces the test's directory in an output.
var tmpPath = regexp.MustCompile(`/[^ :]*/managed\.toml`)

func golden(t *testing.T, name string, got []byte) {
	t.Helper()
	got = tmpPath.ReplaceAll(got, []byte("DIR/managed.toml"))
	p := filepath.Join("testdata", "managed", name+".golden")
	if *updateManaged {
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, got, 0o644)
	}
	want, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %q\nwant %q", name, got, want)
	}
}

func TestManagedShowGoldens(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		code       int
	}{
		{"show-none", "", 0},
		{"show-file", "version = 1\norganisation = \"Acme\"\n\n[locksql.bounds]\ntier = \"write\"\n\n[lox]\nauto_max = { write = \"ask\", ddl = \"deny\" }\nproduction_auto_max = { read = \"ask\" }\nallow_no_upgrade = false\nimage_min = { locksql = \"v0.18.0\" }\negress = [\"*.allowed.internal:5432\"]\n", 0},
		{"show-refused", "version = 1\n[lox]\negress_allow = [\"a:1\"]\n", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			setManaged(t, tc.body)
			var out, errb bytes.Buffer
			if code := run([]string{"managed", "show"}, devNull(t), &out, &errb); code != tc.code {
				t.Errorf("exit %d, want %d: %s", code, tc.code, errb.String())
			}
			golden(t, tc.name, append(out.Bytes(), errb.Bytes()...))
		})
	}
	var out, errb bytes.Buffer
	if code := run([]string{"managed"}, devNull(t), &out, &errb); code != 2 {
		t.Errorf("lox managed: %d", code)
	}
}

// lox run refuses --no-upgrade under allow_no_upgrade = false, and a
// refused file, before anything else: exit 3.
func TestRunManagedRefusals(t *testing.T) {
	for _, tc := range []struct {
		body string
		args []string
		err  string
	}{
		{"version = 1\n[lox]\nallow_no_upgrade = false\n", []string{"run", "--no-upgrade"}, "lox run: --no-upgrade: blocked by company policy: lox.allow_no_upgrade = false\n"},
		{"version = 2\n", []string{"run"}, "lox run: managed: "},
	} {
		setManaged(t, tc.body)
		var out, errb bytes.Buffer
		if code := run(tc.args, devNull(t), &out, &errb); code != 3 || !bytes.Contains(errb.Bytes(), []byte(tc.err)) {
			t.Errorf("%v: %d %q", tc.args, code, errb.String())
		}
	}
	// Allowed: past the managed check (then refused for the pipe).
	setManaged(t, "version = 1\n[lox]\nallow_no_upgrade = true\n")
	var out, errb bytes.Buffer
	if code := run([]string{"run", "--no-upgrade"}, devNull(t), &out, &errb); code != 1 || !bytes.Contains(errb.Bytes(), []byte("not one")) {
		t.Errorf("allowed: %d %q", code, errb.String())
	}
}
