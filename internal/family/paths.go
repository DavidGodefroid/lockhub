package family

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Dir is the Lock Family's directory of a workspace. lea mounts it
// read-only in its agents' containers (and creates it, owned by the
// host user, before it does), so that no agent can change what the hub
// and the locks trust: lockfamily.yaml lives there, and lock up writes
// there what lea needs to reach the locks (up.json).
const Dir = ".lockfamily"

// FileName is the name of the configuration file.
const FileName = "lockfamily.yaml"

// Workspace is the workspace of the lockfamily.yaml at file: the parent
// of its .lockfamily directory, or, for a legacy file at the workspace's
// root, its directory. The same workspace gets the same compose project
// and state directory either way.
func Workspace(file string) string {
	d := filepath.Dir(file)
	if filepath.Base(d) == Dir {
		return filepath.Dir(d)
	}
	return d
}

// Legacy reports a lockfamily.yaml outside a .lockfamily directory: the
// workspace's root is writable by lea's agents.
func Legacy(file string) bool { return filepath.Base(filepath.Dir(file)) != Dir }

// LegacyWarning is what lock says about a legacy lockfamily.yaml.
func LegacyWarning(file string) string {
	ws := Workspace(file)
	return fmt.Sprintf("warning: %s is at the workspace's root, which lea's agents can write; move it where they only read it: mkdir -p %s && mv %s %s",
		file, filepath.Join(ws, Dir), file, filepath.Join(ws, Dir, FileName))
}

// Locate finds the lockfamily.yaml of the workspace dir:
// dir/.lockfamily/lockfamily.yaml, else the legacy dir/lockfamily.yaml,
// else (none yet) the first, where lock add and lock import create it.
func Locate(dir string) string {
	p := filepath.Join(dir, Dir, FileName)
	if _, err := os.Lstat(p); err == nil {
		return p
	}
	if old := filepath.Join(dir, FileName); isFile(old) {
		return old
	}
	return p
}

func isFile(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// ensureDir makes the .lockfamily directory of a new lockfamily.yaml
// (0755: lea's agents read it) and refuses one that is a link or a file.
func ensureDir(file string) error {
	if Legacy(file) {
		return nil
	}
	d := filepath.Dir(file)
	if err := os.Mkdir(d, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if fi, err := os.Lstat(d); err != nil || !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (a symbolic link or a file): remove it and retry", d)
	}
	// Only the user writes what the hub and lea trust.
	return ownDir(d)
}

// SubProjects are the lockfamily.yaml files of the sub-projects of the
// workspace ws (lock import's default): each */.lockfamily/lockfamily.yaml,
// or a legacy */lockfamily.yaml, sorted.
func SubProjects(ws string) []string {
	dirs, _ := filepath.Glob(filepath.Join(ws, "*"))
	var out []string
	for _, d := range dirs {
		if fi, err := os.Stat(d); err != nil || !fi.IsDir() || filepath.Base(d) == Dir {
			continue
		}
		if p := Locate(d); isFile(p) {
			out = append(out, p)
		}
	}
	return out
}
