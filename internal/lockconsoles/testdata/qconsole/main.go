// qconsole is a console built on lockkit's Terminal for the docker e2e
// test: it records its question with the context printed above it as a
// lock does (/run/locksql/k-prod.question), prints a line that is not
// context, and writes the answer it reads to /tmp/a1.
package main

import (
	"context"
	"os"
	"time"

	"github.com/DavidGodefroid/lockkit/console"
)

func main() {
	if err := os.MkdirAll("/run/locksql", 0o700); err != nil {
		panic(err)
	}
	t := console.NewTerminal(os.Stdin, os.Stdout)
	console.RecordQuestions(t, "/run/locksql/k-prod.sock")
	console.PrintContext(t, "\x1b[1;31mPRODUCTION\x1b[0m profile shop-prod")
	console.PrintContext(t, "  + allow write orders")
	t.Println("a result row, never context")
	a, ok := t.Ask(context.Background(), "Apply these changes? [y/N]", time.Minute)
	if !ok {
		os.Exit(1)
	}
	if err := os.WriteFile("/tmp/a1", []byte(a), 0o600); err != nil {
		panic(err)
	}
	t.Println("serving")
	time.Sleep(10 * time.Minute)
}
