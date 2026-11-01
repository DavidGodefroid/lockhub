package family

import (
	"bytes"
	"context"
	"io"
)

// QuietExec runs real commands like Exec, but keeps their stderr (cosign's
// verification report, docker's pull progress) out of the way: it is shown
// when Verbose is set, or when the command fails.
type QuietExec struct {
	Verbose bool
	Stderr  io.Writer
}

// Run implements Runner.
func (q QuietExec) Run(ctx context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	if q.Verbose {
		return Exec{Stderr: q.Stderr}.Run(ctx, stdin, name, args...)
	}
	var buf bytes.Buffer
	out, err := Exec{Stderr: &buf}.Run(ctx, stdin, name, args...)
	if err != nil && q.Stderr != nil {
		q.Stderr.Write(buf.Bytes())
	}
	return out, err
}
