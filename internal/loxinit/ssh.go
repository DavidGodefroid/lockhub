package loxinit

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// KindSSH is an SSH host of the user's ~/.ssh/config, which lockssh
// serves.
const KindSSH = "ssh"

// maxSSHHosts bounds the hosts SSHHosts proposes.
const maxSSHHosts = 8

// SSHHosts are the hosts of the ssh client configuration at path (the
// user's ~/.ssh/config), as lockssh profiles: each Host block with one
// plain name (no pattern), its HostName, User and Port. Nothing but those
// keys is read, and no Include is followed: an IdentityFile is a path,
// named in a note, never read. A host behind ProxyJump or ProxyCommand
// is left out (lockssh has no bastion), as is an IP address (a lock's
// egress reaches host names only).
func SSHHosts(path string) []Source {
	b, ok := readSmall(path)
	if !ok {
		return nil
	}
	var out []Source
	var cur *Source
	var proxied bool
	var identity string
	flush := func() {
		if cur != nil && !proxied && cur.Host != "" && !ipLiteral(cur.Host) && len(out) < maxSSHHosts {
			cur.Notes = append(cur.Notes, "the key file goes in the lock's home: lox run offers to copy yours there")
			if identity != "" {
				cur.Notes[len(cur.Notes)-1] = "the key file goes in the lock's home: lox run offers to copy yours there (IdentityFile " + identity + ")"
			}
			out = append(out, *cur)
		}
		cur, proxied, identity = nil, false, ""
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v := sshLine(sc.Text())
		switch k {
		case "":
			continue
		case "host", "match":
			flush()
			if k == "host" && !strings.ContainsAny(v, "*?!, \t") && v != "" {
				cur = &Source{Kind: KindSSH, Name: v, Host: v, Port: 22, From: []string{"~/.ssh/config (Host " + v + ")"}}
			}
		case "hostname":
			if cur != nil && !strings.Contains(v, "%") {
				cur.Host = strings.ToLower(v)
			}
		case "user":
			if cur != nil && !strings.Contains(v, "%") {
				cur.User = v
			}
		case "port":
			if n, err := strconv.Atoi(v); cur != nil && err == nil && n > 0 && n < 65536 {
				cur.Port = n
			}
		case "proxyjump", "proxycommand":
			proxied = true
		case "identityfile":
			if cur != nil && identity == "" {
				identity = v
			}
		}
	}
	flush()
	return out
}

// sshLine is one ssh_config line's key (lower case) and value: "key
// value" or "key=value", a quoted value unquoted, "" for a comment or a
// blank line.
func sshLine(l string) (string, string) {
	l = strings.TrimSpace(l)
	if l == "" || strings.HasPrefix(l, "#") {
		return "", ""
	}
	i := strings.IndexAny(l, " \t=")
	if i < 0 {
		return strings.ToLower(l), ""
	}
	k, v := l[:i], strings.TrimLeft(l[i:], " \t")
	v = strings.TrimSpace(strings.TrimPrefix(v, "="))
	return strings.ToLower(k), strings.Trim(v, `"`)
}

func ipLiteral(h string) bool {
	h = strings.Trim(h, "[]")
	return strings.Count(h, ":") > 1 || strings.Trim(h, "0123456789.") == ""
}

// readSmall reads a regular file (not a link), bounded.
func readSmall(path string) ([]byte, bool) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, false
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFile+1))
	if err != nil || len(b) > maxFile {
		return nil, false
	}
	return b, true
}

// UserSSHConfig is the user's ssh client configuration, "" when there is
// no home directory.
func UserSSHConfig() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".ssh", "config")
}
