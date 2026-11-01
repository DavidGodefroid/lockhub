package main

import (
	"flag"
	"fmt"
	"io"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

const vaultUsage = "usage: lox vault set --address URL [--namespace NS] [--ca-file PATH] [--file lockfamily.yaml]"

// vaultCmd is lox vault set: the shared vault: block of lockfamily.yaml,
// written (or replaced) with the checks lox add applies. Nothing is
// started; lox up reviews and applies it.
func vaultCmd(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "set" {
		fmt.Fprintln(stderr, vaultUsage)
		return 2
	}
	fs := flag.NewFlagSet("vault set", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	address := fs.String("address", "", "the Vault address, such as https://vault.example.com:8200")
	namespace := fs.String("namespace", "", "the Vault namespace (default: the root namespace)")
	ca := fs.String("ca-file", "", "an absolute path to the Vault CA file (default: the system's CA certificates)")
	pos, err := parse(fs, args[1:])
	if err != nil {
		return 2
	}
	if len(pos) != 0 || *address == "" {
		fmt.Fprintln(stderr, vaultUsage)
		return 2
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox vault set:", err)
		return 1
	}
	if err := family.SetVault(abs, family.Vault{Address: *address, Namespace: *namespace, CAFile: *ca}); err != nil {
		fmt.Fprintln(stderr, "lox vault set:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: vault set; run lox up to review and apply it\n", abs)
	return 0
}
