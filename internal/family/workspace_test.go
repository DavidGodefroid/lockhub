package family

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckWorkspace(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(ws string)
		bad  string // "" accepted, else the directory refused
		want string
	}{
		{"private 0755", func(ws string) {}, "", ""},
		{"missing lock directories", func(ws string) { os.RemoveAll(filepath.Join(ws, ".locksql")) }, "", ""},
		{"workspace 0775", func(ws string) { os.Chmod(ws, 0o775) }, ".", "(mode 0775)"},
		{"workspace 0757", func(ws string) { os.Chmod(ws, 0o757) }, ".", "(mode 0757)"},
		{".lockfamily 0775", func(ws string) { os.Chmod(filepath.Join(ws, Dir), 0o775) }, Dir, "(mode 0775)"},
		{".locksql 0770", func(ws string) { os.Chmod(filepath.Join(ws, ".locksql"), 0o770) }, ".locksql", "(mode 0770)"},
		{".lockfile a link", func(ws string) {
			other := t.TempDir()
			os.Symlink(other, filepath.Join(ws, ".lockfile"))
		}, ".lockfile", "not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ws, _ := filepath.EvalSymlinks(t.TempDir())
			os.Chmod(ws, 0o755)
			for _, d := range []string{Dir, ".locksql"} {
				os.Mkdir(filepath.Join(ws, d), 0o755)
				os.Chmod(filepath.Join(ws, d), 0o755)
			}
			tc.make(ws)
			err := CheckWorkspace(ws)
			if tc.bad == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			d := filepath.Join(ws, tc.bad)
			if err == nil || !strings.HasPrefix(err.Error(), d+" ") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %s refused (%s)", err, d, tc.want)
			}
			if strings.Contains(tc.want, "mode") && !strings.Contains(err.Error(), "chmod go-w "+d) {
				t.Fatalf("no chmod hint: %v", err)
			}
		})
	}
}

// lox up (and lox run's start) refuses a group-writable workspace before
// it reads anything.
func TestUpRefusesGroupWritableWorkspace(t *testing.T) {
	ws, _ := filepath.EvalSymlinks(t.TempDir())
	os.Chmod(ws, 0o775)
	u := &Up{File: filepath.Join(ws, Dir, FileName)}
	if err := u.Do(context.Background()); err == nil || !strings.Contains(err.Error(), "chmod go-w "+ws) {
		t.Fatalf("err = %v", err)
	}
}
