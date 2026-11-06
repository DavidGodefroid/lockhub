// Command shipped prints the release of a lock this lox ships with
// (family.ShippedLocks), for the e2e jobs that check out a lock's
// repository at the release lox add pins: they cannot drift from it.
//
//	go run ./ci/e2e/shipped locklog
package main

import (
	"fmt"
	"os"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: shipped <lock>")
		os.Exit(2)
	}
	v, ok := family.ShippedLocks[os.Args[1]]
	if !ok {
		fmt.Fprintln(os.Stderr, "shipped: no shipped release for", os.Args[1])
		os.Exit(1)
	}
	fmt.Println(v)
}
