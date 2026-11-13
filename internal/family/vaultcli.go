package family

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// vaultCLILine is the summary line of a lock with vault_token: cli.
const vaultCLILine = "lock %s vault token from the host's Vault CLI"

// VaultCLI is what lox run needs to hand the locks with vault_token: cli
// the host's Vault CLI token, as the last confirmed lox run applied it
// (applied.json): never the workspace's lockfamily.yaml, which agents
// can write. The token goes only to the Vault a human reviewed, checked
// against the paths a human reviewed.
type VaultCLI struct {
	Address, Namespace string
	// CAFile is the reviewed vault.ca_file ("" none); CASHA256 its
	// reviewed digest (hex).
	CAFile, CASHA256 string
	// Locks are the instances with vault_token: cli, each with the
	// vault_path of its reviewed profile ("" when the review shows none:
	// the token is then never used for it).
	Locks map[string]string
}

// AppliedVaultCLI reads the locks with vault_token: cli from the summary
// the last confirmed lox run applied, in the state directory state. nil:
// none (or nothing applied yet).
func AppliedVaultCLI(state string) (*VaultCLI, error) {
	b, err := os.ReadFile(filepath.Join(state, "applied.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var a Applied
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("applied.json: %w", err)
	}
	return vaultCLIOf(a.Summary)
}

// vaultCLIOf reads VaultCLI from an applied summary (Summary, and the
// profile and CA lines lox up adds to it).
func vaultCLIOf(sum []string) (*VaultCLI, error) {
	cli := map[string]bool{}
	addr, ns := map[string]string{}, map[string]string{}
	typ, prof := map[string]string{}, map[string]string{}
	lines := map[string][]string{} // by lock type
	v := &VaultCLI{Locks: map[string]string{}}
	for _, l := range sum {
		if rest, ok := strings.CutPrefix(l, "vault ca_file "); ok {
			path, sha, ok := strings.Cut(rest, " sha256:")
			if !ok {
				return nil, errors.New("applied.json: a vault ca_file line without its digest")
			}
			v.CAFile, v.CASHA256 = path, sha
			continue
		}
		if rest, ok := strings.CutPrefix(l, "profile "); ok {
			if t, line, ok := strings.Cut(rest, " "); ok {
				lines[t] = append(lines[t], line)
			}
			continue
		}
		rest, ok := strings.CutPrefix(l, "lock ")
		if !ok {
			continue
		}
		n, what, ok := strings.Cut(rest, " ")
		if !ok {
			continue
		}
		switch {
		case l == fmt.Sprintf(vaultCLILine, n):
			cli[n] = true
		case strings.HasPrefix(what, "vault VAULT_ADDR="):
			addr[n] = strings.TrimPrefix(what, "vault VAULT_ADDR=")
		case strings.HasPrefix(what, "vault VAULT_NAMESPACE="):
			ns[n] = strings.TrimPrefix(what, "vault VAULT_NAMESPACE=")
		case strings.HasPrefix(what, "type "):
			typ[n] = strings.TrimPrefix(what, "type ")
		case strings.HasPrefix(what, "profile "):
			prof[n] = strings.TrimPrefix(what, "profile ")
		}
	}
	if len(cli) == 0 {
		return nil, nil
	}
	first := true
	for n := range cli {
		a := addr[n]
		if a == "" {
			return nil, fmt.Errorf("applied.json: lock %s takes the Vault CLI's token but names no Vault address", n)
		}
		if !first && (a != v.Address || ns[n] != v.Namespace) {
			return nil, errors.New("applied.json: the locks with vault_token: cli name different Vaults")
		}
		first = false
		v.Address, v.Namespace = a, ns[n]
		t := typ[n]
		f := ProfileFacts(&Profile{Lines: lines[t]}, t, LockProfile(Lock{Type: t, Profile: prof[n]}))
		path := f.VaultPath
		// As the short review reads it: no credentials line is vault.
		if f.Odd["vault_path"] != "" || f.Odd["credentials"] != "" || (f.Credentials != "" && f.Credentials != "vault") {
			path = ""
		}
		v.Locks[n] = path
	}
	return v, nil
}

// CA is the reviewed CA's PEM, read again and checked against the
// reviewed digest (nil: no CA, the system's are used).
func (v *VaultCLI) CA() ([]byte, error) {
	if v.CAFile == "" {
		return nil, nil
	}
	b, sha, err := readCA(v.CAFile)
	if err != nil {
		return nil, err
	}
	if sha != v.CASHA256 {
		return nil, errors.New("vault.ca_file changed since the last lox run's review")
	}
	return b, nil
}
