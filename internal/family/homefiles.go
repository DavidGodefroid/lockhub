package family

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall"
)

// A locksql profile names files its console reads: tls_ca, tls_cert,
// tls_key and, with ssh auth = "key", ssh.key. They are read inside the
// console's container, where a leading "~/" is the console account's
// home, its home volume (locksql's config.ExpandHome). lox run checks
// them there before the console starts, so that a missing file shows in
// the review, not after the console's questions.

// FileKey is a file key of a profile: Path as the profile writes it.
type FileKey struct {
	Key, Path string
}

// private tells whether the key names a private key, which no one but
// the console account may read.
func (f FileKey) private() bool { return f.Key == "tls_key" || f.Key == "ssh.key" }

// ConsoleHome is the console account's home in a lock's image, where
// its home volume is mounted.
func ConsoleHome(typ string) string { return "/home/" + typ }

// ExpandHome resolves a leading "~/" (or a lone "~") of a file key's path
// to home, as locksql does; any other path is returned as is.
func ExpandHome(p, home string) string {
	if p == "~" {
		return home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return path.Join(home, rest)
	}
	return p
}

// ProfileFileKeys are the file keys the profile named profile (empty: the
// only one) sets in p, in locksql's order. odd are the keys whose value
// the review cannot read exactly (an escape, not a string): not checked.
func ProfileFileKeys(p *Profile, profile string) (keys []FileKey, odd []string) {
	secs, order := profileSections(p)
	name := profile
	if name == "" && len(order) == 1 {
		name = order[0]
	}
	sec, ok := secs[name]
	if !ok {
		return nil, nil
	}
	str := func(k string) (string, bool) {
		raw, ok := sec[k]
		if !ok {
			return "", false
		}
		v, kind, ok := strictValue(raw)
		if !ok || kind != 's' {
			odd = append(odd, k)
			return "", false
		}
		return v, v != ""
	}
	for _, k := range []string{"tls_ca", "tls_cert", "tls_key"} {
		if v, ok := str(k); ok {
			keys = append(keys, FileKey{k, v})
		}
	}
	if raw, ok := sec["ssh.auth"]; ok {
		if v, kind, ok := strictValue(raw); ok && kind == 's' && v == "key" {
			if v, ok := str("ssh.key"); ok {
				keys = append(keys, FileKey{"ssh.key", v})
			}
		}
	}
	return keys, odd
}

// homeFilesScript reads one path per line on stdin and prints, per path
// and in order, what it is to the account it runs as: missing, notfile,
// unreadable, or ok and its mode in octal.
const homeFilesScript = `while IFS= read -r p; do if [ ! -e "$p" ]; then echo missing; elif [ ! -f "$p" ]; then echo notfile; elif [ ! -r "$p" ]; then echo unreadable; else echo "ok $(stat -L -c %a "$p")"; fi; done`

// homeCopyScript writes its stdin to the path $1, private (umask 077),
// making its directory: locksql doctor's own copy command.
const homeCopyScript = `umask 077 && mkdir -p "$(dirname "$1")" && cat > "$1"`

// HomeFile is a file key as lox run found it in the console's container.
type HomeFile struct {
	FileKey
	// Resolved is Path with "~/" expanded to the console's home.
	Resolved string
	// State: "ok", "missing", "notfile", "unreadable", or "" (not checked).
	State string
	// Mode is the file's permission bits, for "ok".
	Mode uint32
}

// InHome tells whether the file lives in the console's home volume
// (where it can be copied to).
func (h HomeFile) InHome(typ string) bool {
	return strings.HasPrefix(h.Resolved, ConsoleHome(typ)+"/")
}

// checkHomeFiles runs homefiles-<n> with the lock's resolved paths and
// reads its answer. A path with a newline is never sent: it is reported
// "" (not checked).
func (u *Up) checkHomeFiles(ctx context.Context, project string, composeYAML []byte, n, typ string, keys []FileKey) ([]HomeFile, error) {
	files := make([]HomeFile, len(keys))
	var in strings.Builder
	var sent []int
	for i, k := range keys {
		files[i] = HomeFile{FileKey: k, Resolved: ExpandHome(k.Path, ConsoleHome(typ))}
		if strings.ContainsAny(files[i].Resolved, "\n\r") {
			continue
		}
		in.WriteString(files[i].Resolved + "\n")
		sent = append(sent, i)
	}
	if len(sent) == 0 {
		return files, nil
	}
	out, err := u.runSetup(ctx, project, composeYAML, []byte(in.String()), "homefiles-"+n)
	if err != nil {
		return files, err
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) != len(sent) {
		return files, fmt.Errorf("homefiles-%s answered %d line(s) for %d file(s)", n, len(lines), len(sent))
	}
	for j, i := range sent {
		state, mode, _ := strings.Cut(strings.TrimSpace(lines[j]), " ")
		switch state {
		case "missing", "notfile", "unreadable":
			files[i].State = state
		case "ok":
			var m uint32
			if _, err := fmt.Sscanf(mode, "%o", &m); err != nil || m > 0o7777 {
				return files, fmt.Errorf("homefiles-%s: mode %q of %s", n, mode, files[i].Key)
			}
			files[i].State, files[i].Mode = "ok", m
		default:
			return files, fmt.Errorf("homefiles-%s: unexpected answer %q", n, lines[j])
		}
	}
	return files, nil
}

// homeVolume is the docker volume of a lock's home (compose's name of
// <instance>-home in the workspace's project).
func homeVolume(project, n string) string { return project + "_" + n + "-home" }

// consoleRun is the docker run of the lock's image, as its console's
// account, on its home volume, with no network.
func consoleRun(project, n string, l Lock, stdin bool, entrypoint string) string {
	k := Kinds[l.Type]
	i := ""
	if stdin {
		i = " -i"
	}
	return "docker run --rm" + i + " --network none --user " + k.UID + ":" + k.GID + " -v " +
		shq(homeVolume(project, n)+":"+ConsoleHome(l.Type)) + " --entrypoint " + entrypoint + " " + shq(l.Image)
}

// CopyCommand is the command that copies the host file src (its base
// name when "") into the lock's home volume at h.Resolved, private, as
// the console's account: locksql doctor's command, on the volume (the
// console may not run yet).
func CopyCommand(project, n string, l Lock, h HomeFile, src string) string {
	if src == "" {
		src = path.Base(h.Resolved)
	}
	script := "umask 077 && mkdir -p " + shq(path.Dir(h.Resolved)) + " && cat > " + shq(h.Resolved)
	return consoleRun(project, n, l, true, "/bin/sh") + " -c " + shq(script) + " < " + shq(src)
}

// ChmodCommand makes h private, in the lock's home volume.
func ChmodCommand(project, n string, l Lock, h HomeFile) string {
	return consoleRun(project, n, l, false, "chmod") + " 600 " + shq(h.Resolved)
}

// HomeFileWarnings are the review's rows for a lock's file keys: one per
// file that the console would refuse or that others can read; a present,
// private file says nothing. odd are the keys ProfileFileKeys could not
// read.
func HomeFileWarnings(project, n string, l Lock, files []HomeFile, odd []string, checkErr error) []string {
	var out []string
	for _, k := range odd {
		out = append(out, fmt.Sprintf("%s: not a plain string in the profile, not checked", k))
	}
	if checkErr != nil {
		return append(out, fmt.Sprintf("the profile's files could not be checked (%v): the console checks them at its start", checkErr))
	}
	home := ConsoleHome(l.Type)
	for _, h := range files {
		where := h.Resolved
		if h.Resolved != h.Path {
			where = h.Resolved + " (" + h.Path + ")"
		}
		switch h.State {
		case "":
			out = append(out, fmt.Sprintf("%s: %q not checked (a line break in the path)", h.Key, h.Path))
		case "missing":
			switch {
			case h.InHome(l.Type):
				out = append(out, fmt.Sprintf("%s: %s is not in the lock's home volume; copy it there: %s", h.Key, where, CopyCommand(project, n, l, h, "")))
			case !path.IsAbs(h.Resolved):
				out = append(out, fmt.Sprintf("%s: %s not found from the console's working directory; write it ~/%s and copy it into the lock's home", h.Key, where, path.Base(h.Resolved)))
			default:
				out = append(out, fmt.Sprintf("%s: %s not found in the lock's image; write it ~/%s (%s) and copy it into the lock's home", h.Key, where, path.Base(h.Resolved), home))
			}
		case "notfile":
			out = append(out, fmt.Sprintf("%s: %s is not a regular file", h.Key, where))
		case "unreadable":
			out = append(out, fmt.Sprintf("%s: %s is not readable by the console account", h.Key, where))
		case "ok":
			if h.private() && h.Mode&0o077 != 0 {
				fix := "chmod 600 " + shq(h.Resolved)
				if h.InHome(l.Type) {
					fix = ChmodCommand(project, n, l, h)
				}
				out = append(out, fmt.Sprintf("%s: %s is readable by others (mode %04o): %s", h.Key, where, h.Mode, fix))
			}
		}
	}
	return out
}

// maxHomeFile bounds a file lox add copies into a lock's home: PEM files
// and SSH keys are small.
const maxHomeFile = 1 << 20

// readHostFile reads a host file to copy into a lock's home: a regular
// file (links are not followed) of at most maxHomeFile bytes.
func readHostFile(p string) ([]byte, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		var pe *os.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxHomeFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxHomeFile {
		return nil, fmt.Errorf("%s: larger than %d KiB", p, maxHomeFile>>10)
	}
	return b, nil
}

// shq quotes s for a POSIX shell when it needs it.
func shq(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@%_+=:,./-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// homeCopy is a host file lox add copies into a lock's home once the
// human said yes.
type homeCopy struct {
	lock, key, dst string
	content        []byte
}

// askCopies offers, for each file of lock n missing from its home, a
// host file to copy there. An empty answer leaves the file to the
// command the review gives; a file that cannot be read is said and asked
// again.
func (u *Up) askCopies(ctx context.Context, n string, missing []HomeFile) ([]homeCopy, error) {
	var out []homeCopy
	for _, h := range missing {
		for {
			fmt.Fprintf(u.Out, "Copy %s into the lock's home as %s, from the host file (optional: empty = not now, with the command above): ", h.Key, h.Resolved)
			a, err := readAnswer(ctx, u.In)
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			a = strings.TrimSpace(a)
			if a == "" {
				break
			}
			if rest, ok := strings.CutPrefix(a, "~/"); ok {
				if home, herr := os.UserHomeDir(); herr == nil {
					a = path.Join(home, rest)
				}
			}
			b, rerr := readHostFile(a)
			if rerr != nil {
				fmt.Fprintf(u.Out, "%s: %v\n", h.Key, rerr)
				if err != nil {
					break // end of input
				}
				continue
			}
			out = append(out, homeCopy{lock: n, key: h.Key, dst: h.Resolved, content: b})
			break
		}
	}
	return out, nil
}
