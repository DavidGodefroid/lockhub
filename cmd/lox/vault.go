package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

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
	namespace := fs.String("namespace", "", "the Vault namespace (omitted: the current one is kept; \"\": the root namespace)")
	ca := fs.String("ca-file", "", "an absolute path to the Vault CA file (omitted: the current one is kept; \"\": the system's CA certificates)")
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
	v := family.Vault{Address: *address, Namespace: *namespace, CAFile: *ca}
	given := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { given[f.Name] = true })
	if !given["namespace"] || !given["ca-file"] {
		// An omitted flag keeps the current value; an explicit "" clears it.
		// Read leniently: the file may be one its vault block makes invalid,
		// which this command repairs.
		cur, err := currentVault(abs)
		if err != nil {
			fmt.Fprintln(stderr, "lox vault set:", err)
			return 1
		}
		if !given["namespace"] {
			v.Namespace = cur.Namespace
		}
		if !given["ca-file"] {
			v.CAFile = cur.CAFile
		}
	}
	if err := family.SetVault(abs, v); err != nil {
		fmt.Fprintln(stderr, "lox vault set:", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s: vault set; run lox run to review and apply it\n", abs)
	return 0
}

// currentVault reads the vault block's namespace and ca_file from the file
// without validating the file. Unparseable YAML is an error that names the
// file, never its content.
func currentVault(path string) (family.Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return family.Vault{}, err
	}
	var doc struct {
		Vault struct {
			Namespace string `yaml:"namespace"`
			CAFile    string `yaml:"ca_file"`
		} `yaml:"vault"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return family.Vault{}, fmt.Errorf("%s: not readable YAML", path)
	}
	return family.Vault{Namespace: doc.Vault.Namespace, CAFile: doc.Vault.CAFile}, nil
}
