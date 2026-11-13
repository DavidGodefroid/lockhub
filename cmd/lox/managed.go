package main

import (
	"context"
	"fmt"
	"io"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

const managedUsage = "usage: lox managed show"

// managedCmd is lox managed show: the host's managed file as lox run
// reads it (path, organisation, fingerprint, signature, the [lox] rules
// and the tools it has a section for). No file: "no managed
// configuration", exit 0; a file refused: the error, exit 3.
func managedCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "show" {
		fmt.Fprintln(stderr, managedUsage)
		return 2
	}
	m, err := family.LoadManaged(context.Background())
	if err != nil {
		fmt.Fprintln(stderr, "lox managed show:", err)
		return exitManaged
	}
	for _, l := range m.Show() {
		fmt.Fprintln(stdout, l)
	}
	return 0
}
