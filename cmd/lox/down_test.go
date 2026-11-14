package main

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// engine is a Docker engine with the containers and networks of one
// project, which docker rm and docker network rm remove.
type engine struct {
	project     string
	ctrs, nets  []string
	calls       []string
	volumesSeen bool
}

func (e *engine) Run(_ context.Context, _ []byte, name string, args ...string) ([]byte, error) {
	line := name + " " + strings.Join(args, " ")
	e.calls = append(e.calls, line)
	if strings.Contains(line, "volume") {
		e.volumesSeen = true
	}
	switch {
	case line == "docker ps -a -q --no-trunc --filter label=com.docker.compose.project="+e.project:
		return []byte(strings.Join(e.ctrs, "\n")), nil
	case line == "docker network ls -q --filter label=com.docker.compose.project="+e.project:
		return []byte(strings.Join(e.nets, "\n")), nil
	case len(args) > 0 && args[0] == "rm":
		e.ctrs = slices.DeleteFunc(e.ctrs, func(c string) bool { return slices.Contains(args[1:], c) })
	case len(args) > 1 && args[0] == "network" && args[1] == "rm":
		e.nets = slices.DeleteFunc(e.nets, func(n string) bool { return slices.Contains(args[2:], n) })
	}
	return nil, nil
}

// lox down stops the containers and networks of the workspace, never a
// volume, and is idempotent.
func TestDown(t *testing.T) {
	e := &engine{project: "lockfamily-0a0b0c0d", ctrs: []string{"hub", "lock"}, nets: []string{"n1"}}
	var out, errb strings.Builder
	if code := down(context.Background(), e, e.project, &out, &errb); code != 0 || !strings.Contains(out.String(), "stopped 2 container(s) and removed 1 network(s)") {
		t.Fatalf("%d %q %q", code, out.String(), errb.String())
	}
	if len(e.ctrs) != 0 || len(e.nets) != 0 || e.volumesSeen || !slices.Contains(e.calls, "docker stop hub lock") {
		t.Errorf("left %v %v, calls %q", e.ctrs, e.nets, e.calls)
	}
	out.Reset()
	if code := down(context.Background(), e, e.project, &out, &errb); code != 0 || !strings.Contains(out.String(), "nothing runs for this workspace") {
		t.Errorf("again: %d %q %q", code, out.String(), errb.String())
	}
}
