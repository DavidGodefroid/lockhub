// Command lock is the Lock Family CLI on the host: it sets up the hub and
// the locks of a workspace (lock up) and answers approvals in a terminal
// (lock approve). This version only reports its version; the commands
// arrive with the issues that add them.
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at build time (-X main.version=X.Y.Z).
var version = "dev"

const usage = `lock: the Lock Family CLI

Usage:
  lock version   print the version
  lock help      show this help

Coming: lock up, lock approve, lock audit verify, lock add, lock import, lock doctor.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version", "--version":
		fmt.Fprintln(stdout, "lock", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "lock: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
