package family

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// answers is a Runner that answers by substring of the command line.
type answers struct {
	out   map[string]string
	fail  []string
	calls []string
}

func (a *answers) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	a.calls = append(a.calls, line)
	for _, f := range a.fail {
		if strings.Contains(line, f) {
			return nil, errors.New("refused")
		}
	}
	for k, v := range a.out {
		if strings.Contains(line, k) {
			return []byte(v), nil
		}
	}
	return nil, nil
}

// healthy lays out what a confirmed lock up leaves: state, keys, socket.
func healthy(t *testing.T) (*Doctor, *answers) {
	t.Helper()
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	run := filepath.Join(w.dir, "run")
	// Unix socket paths are short: listen in a short dir, then move it.
	sd, err := os.MkdirTemp("", "dr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sd) })
	l, err := net.Listen("unix", filepath.Join(sd, "s"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	os.Chmod(filepath.Join(sd, "s"), 0o660)
	if err := os.Rename(filepath.Join(sd, "s"), filepath.Join(run, "lockhub", "facade.sock")); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(w.dir, "root")
	write(t, filepath.Join(root, "etc", "passwd"), "root:x:0:0:root:/root:/bin/bash\ndavid:x:1000:1000::/home/david:/bin/bash\n")
	write(t, filepath.Join(root, "etc", "group"), "root:x:0:\n")
	a := &answers{out: map[string]string{
		"info --format": "27.3.1\n",
		"image inspect": "sha256:abc\n",
		"ps --all --format json": `{"Service":"lockhub","State":"running"}
{"Service":"lock-crm-prod","State":"running"}
{"Service":"lock-events","State":"running"}
`,
		"network inspect": "true\n",
	}}
	return &Doctor{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: run, Root: root, Run: a}, a
}

func doc(t *testing.T, d *Doctor) (string, int) {
	var out strings.Builder
	d.Out = &out
	n := d.Do(context.Background())
	return out.String(), n
}

func TestDoctorHealthy(t *testing.T) {
	d, _ := healthy(t)
	out, n := doc(t, d)
	if n != 0 || strings.Contains(out, "FAIL") || strings.Contains(out, "warn") {
		t.Fatalf("%d problems:\n%s", n, out)
	}
	for _, want := range []string{"lockfamily.yaml", "engine", "hub key", "facade socket", "lock-events running", "internal"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
}

func TestDoctorFindsProblems(t *testing.T) {
	for name, tc := range map[string]struct {
		break_ func(d *Doctor, a *answers)
		want   string
	}{
		"engine down": {func(d *Doctor, a *answers) { a.fail = []string{"info"} }, "FAIL engine"},
		"lock stopped": {func(d *Doctor, a *answers) {
			a.out["ps --all --format json"] = `[{"Service":"lockhub","State":"running"},{"Service":"lock-crm-prod","State":"exited"}]`
		}, "FAIL lock-crm-prod exited"},
		"network not internal": {func(d *Doctor, a *answers) { a.out["network inspect"] = "false\n" }, "FAIL network"},
		"socket open to others": {func(d *Doctor, a *answers) {
			os.Chmod(filepath.Join(d.Runtime, "lockhub", "facade.sock"), 0o666)
		}, "FAIL facade socket"},
		"socket is a file": {func(d *Doctor, a *answers) {
			p := filepath.Join(d.Runtime, "lockhub", "facade.sock")
			os.Remove(p)
			os.WriteFile(p, nil, 0o600)
		}, "FAIL facade socket"},
		"state dir open": {func(d *Doctor, a *answers) { os.Chmod(d.State, 0o755) }, "FAIL state"},
		"bad hub key": {func(d *Doctor, a *answers) {
			os.WriteFile(filepath.Join(d.State, "hub.pub"), []byte("nope\n"), 0o644)
		}, "FAIL hub key"},
		"lock without key": {func(d *Doctor, a *answers) {
			os.WriteFile(d.File, []byte(strings.Replace(yamlConf(""), "  events:", "  docs:\n    type: lockfile\n    image: "+fileImg+"\n  events:", 1)), 0o644)
		}, "FAIL hub lock list"},
		"yaml changed": {func(d *Doctor, a *answers) {
			os.WriteFile(d.File, []byte(strings.Replace(yamlConf(""), "    production: true\n", "", 1)), 0o644)
		}, "warn lockfamily.yaml changed"},
		"yaml invalid":  {func(d *Doctor, a *answers) { os.WriteFile(d.File, []byte("version: 2\n"), 0o644) }, "FAIL lockfamily.yaml"},
		"image missing": {func(d *Doctor, a *answers) { a.fail = []string{"image inspect"} }, "warn image"},
	} {
		t.Run(name, func(t *testing.T) {
			d, a := healthy(t)
			tc.break_(d, a)
			out, n := doc(t, d)
			if !strings.Contains(out, tc.want) {
				t.Fatalf("no %q:\n%s", tc.want, out)
			}
			if strings.HasPrefix(tc.want, "FAIL") && n == 0 {
				t.Errorf("FAIL not counted:\n%s", out)
			}
		})
	}
}

func TestDoctorReportsHostAccountsNeverRemoves(t *testing.T) {
	d, a := healthy(t)
	write(t, filepath.Join(d.Root, "etc", "passwd"), "root:x:0:0::/root:/bin/sh\nlocksql:x:10000:10000::/home/locksql:/bin/sh\nlockmq:x:10001:10001::/nonexistent:/usr/sbin/nologin\n")
	write(t, filepath.Join(d.Root, "etc", "group"), "locksql-clients:x:10002:david\n")
	write(t, filepath.Join(d.Root, "etc", "locksql", "system.toml"), "x = 1\n")
	os.MkdirAll(filepath.Join(d.Root, "run", "lockmq"), 0o755)
	out, n := doc(t, d)
	if n != 0 {
		t.Errorf("leftover accounts are warnings, not failures: %d\n%s", n, out)
	}
	for _, want := range []string{"sudo userdel locksql", "sudo groupdel locksql-clients", "sudo rm -r /etc/locksql", "sudo userdel lockmq", "sudo rm -r /run/lockmq"} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "lockfile") {
		t.Errorf("lockfile has no account:\n%s", out)
	}
	for _, c := range a.calls {
		if strings.Contains(c, "userdel") || strings.Contains(c, "rm ") || strings.Contains(c, "sudo") {
			t.Errorf("doctor ran %q", c)
		}
	}
	if _, err := os.Stat(filepath.Join(d.Root, "etc", "locksql", "system.toml")); err != nil {
		t.Error("removed")
	}
}

func TestDoctorWritesNothing(t *testing.T) {
	root := t.TempDir()
	file := write(t, filepath.Join(root, "ws", "lockfamily.yaml"), yamlConf(""))
	d := &Doctor{File: file, State: filepath.Join(root, "state"), Runtime: filepath.Join(root, "run"), Root: filepath.Join(root, "sys"), Run: &answers{out: map[string]string{"info": "27\n"}}}
	out, n := doc(t, d)
	if n == 0 || !strings.Contains(out, "lock up") {
		t.Errorf("a workspace never brought up is not healthy:\n%s", out)
	}
	for _, p := range []string{d.State, d.Runtime, filepath.Join(root, "ws", ".lockfamily")} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("doctor created %s", p)
		}
	}
}
