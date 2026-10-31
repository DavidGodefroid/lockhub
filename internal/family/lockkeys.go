package family

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/keys"
)

// lockKeysFile is the format of LockKeysFile and of each file of
// LockKeysDir: {"locks": {"<instance>": {"public_key": "<base64>"}}}. A
// file of LockKeysDir also names its workspace (only pinLockKeys reads
// those, leniently).
type lockKeysFile struct {
	Workspace string             `json:"workspace,omitempty"`
	Locks     map[string]lockKey `json:"locks"`
}

type lockKey struct {
	PublicKey string `json:"public_key"`
}

// pinned is one instance as one workspace's file pins it.
type pinned struct {
	inst, key, file, ws string
}

func (p pinned) where() string {
	ws := p.ws
	if ws == "" {
		ws = "an unknown workspace"
	}
	return ws + " (" + filepath.Join(LockKeysDir, p.file) + ")"
}

// pinLockKeys records the lock keys pubs of workspace ws (compose project
// project, by instance) in dir's LockKeysDir, then writes LockKeysFile as
// the union of every workspace's, so that host facades (lox approve,
// lea's deck) check the answers of every workspace's locks. It returns
// warnings for what it left out of the union (fail closed: no clear
// values for those instances): an instance two workspaces pin with
// different keys, a key two instances share (keys.LoadLocks would refuse
// the whole file), another workspace's file or key that does not parse.
// A file of a workspace that no longer exists is never removed here (its
// path may only be unmounted): the warning names it. One lox up at a
// time rewrites the union (a lock on dir).
func pinLockKeys(dir, project, ws string, pubs map[string]string) ([]string, error) {
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	d := filepath.Join(dir, LockKeysDir)
	if err := privateDir(d); err != nil {
		return nil, err
	}
	ownName := project + ".json"
	own := filepath.Join(d, ownName)
	if len(pubs) == 0 {
		if err := os.Remove(own); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	} else {
		f := lockKeysFile{Workspace: ws, Locks: map[string]lockKey{}}
		for n, k := range pubs {
			f.Locks[n] = lockKey{PublicKey: k}
		}
		b, _ := json.MarshalIndent(f, "", "  ")
		if err := writeAtomic(own, append(b, '\n'), 0o600); err != nil {
			return nil, err
		}
	}
	ents, err := os.ReadDir(d)
	if err != nil {
		return nil, err
	}
	var warns []string
	var all []pinned
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var f lockKeysFile
		b, err := os.ReadFile(filepath.Join(d, e.Name()))
		if err == nil {
			err = json.Unmarshal(b, &f)
		}
		if err != nil {
			warns = append(warns, fmt.Sprintf("%s: unreadable, left out (%v): delete it if its workspace is gone, or lox up there", filepath.Join(LockKeysDir, e.Name()), err))
			continue
		}
		for n, l := range f.Locks {
			k, err := base64.StdEncoding.DecodeString(l.PublicKey)
			if !keys.ValidInstance(n) || err != nil || len(k) != ed25519.PublicKeySize {
				what := "an instance without a valid name"
				if keys.ValidInstance(n) {
					what = fmt.Sprintf("instance %q has no valid key", n)
				}
				warns = append(warns, fmt.Sprintf("%s: %s, left out", filepath.Join(LockKeysDir, e.Name()), what))
				continue
			}
			// The canonical spelling: two spellings of one key are one key.
			all = append(all, pinned{inst: n, key: keys.Public(ed25519.PublicKey(k)), file: e.Name(), ws: f.Workspace})
		}
	}
	byName := map[string][]pinned{}
	byKey := map[string][]pinned{}
	for _, p := range all {
		byName[p.inst] = append(byName[p.inst], p)
		byKey[p.key] = append(byKey[p.key], p)
	}
	bad := map[string]bool{}
	for n, ps := range byName {
		for _, p := range ps[1:] {
			if p.key != ps[0].key {
				bad[n] = true
				warns = append(warns, fmt.Sprintf("lock instance %s has another key in %s than in %s: clear values of its tickets cannot be shown; rename it in one workspace, or delete the file of a workspace that no longer exists", n, ps[0].where(), p.where()))
				break
			}
		}
	}
	for _, ps := range byKey {
		if !slices.ContainsFunc(ps[1:], func(p pinned) bool { return p.inst != ps[0].inst }) {
			continue
		}
		// Every instance on the key is left out, however many share it.
		var names []string
		for _, p := range ps {
			bad[p.inst] = true
			names = append(names, p.inst+" in "+p.where())
		}
		slices.Sort(names)
		warns = append(warns, fmt.Sprintf("lock instances %s share a key: clear values of their tickets cannot be shown; give each its own lock home, or delete the file of a workspace that no longer exists", strings.Join(names, ", ")))
	}
	union := lockKeysFile{Locks: map[string]lockKey{}}
	for n, ps := range byName {
		if !bad[n] {
			union.Locks[n] = lockKey{PublicKey: ps[0].key}
		}
	}
	slices.Sort(warns)
	b, _ := json.MarshalIndent(union, "", "  ")
	return warns, writeAtomic(filepath.Join(dir, LockKeysFile), append(b, '\n'), 0o600)
}

// lockDir takes an exclusive lock on dir (a lock file in it) until the
// returned function runs.
func lockDir(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		f.Close()
	}, nil
}
