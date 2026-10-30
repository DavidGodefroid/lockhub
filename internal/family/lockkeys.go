package family

import (
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
// LockKeysDir: {"locks": {"<instance>": {"public_key": "<base64>"}}}.
type lockKeysFile struct {
	Locks map[string]lockKey `json:"locks"`
}

type lockKey struct {
	PublicKey string `json:"public_key"`
}

// pinLockKeys records the lock keys pubs of workspace project (by
// instance) in dir's LockKeysDir, then writes LockKeysFile as the union
// of every workspace's, so that host facades (lock approve, lea's deck)
// check the answers of every workspace's locks. An instance that two
// workspaces pin with different keys, or a key two instances share, is
// left out of the union (fail closed: no clear values for it) and
// returned. One lock up at a time rewrites the union (a lock on dir).
func pinLockKeys(dir, project string, pubs map[string]string) ([]string, error) {
	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	d := filepath.Join(dir, LockKeysDir)
	if err := privateDir(d); err != nil {
		return nil, err
	}
	own := filepath.Join(d, project+".json")
	if len(pubs) == 0 {
		if err := os.Remove(own); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	} else {
		f := lockKeysFile{Locks: map[string]lockKey{}}
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
	byName := map[string]string{} // instance → key
	byKey := map[string]string{}  // key → instance
	bad := map[string]bool{}
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(d, e.Name()))
		if err != nil {
			return nil, err
		}
		var f lockKeysFile
		if err := json.Unmarshal(b, &f); err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(d, e.Name()), err)
		}
		for n, l := range f.Locks {
			if !keys.ValidInstance(n) {
				return nil, fmt.Errorf("%s: bad instance name %q", filepath.Join(d, e.Name()), n)
			}
			if k, ok := byName[n]; ok && k != l.PublicKey {
				bad[n] = true
			}
			if m, ok := byKey[l.PublicKey]; ok && m != n {
				bad[n], bad[m] = true, true
			}
			byName[n], byKey[l.PublicKey] = l.PublicKey, n
		}
	}
	union := lockKeysFile{Locks: map[string]lockKey{}}
	var conflicts []string
	for n, k := range byName {
		if bad[n] {
			conflicts = append(conflicts, n)
			continue
		}
		union.Locks[n] = lockKey{PublicKey: k}
	}
	slices.Sort(conflicts)
	b, _ := json.MarshalIndent(union, "", "  ")
	return conflicts, writeAtomic(filepath.Join(dir, LockKeysFile), append(b, '\n'), 0o600)
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
