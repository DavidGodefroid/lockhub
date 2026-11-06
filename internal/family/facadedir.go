package family

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// ownedByMe reports whether fi is owned by this process's user.
func ownedByMe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) == os.Getuid()
}

// owner is fi's uid, -1 when the system does not say.
func owner(fi os.FileInfo) int {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid)
	}
	return -1
}

// facadeDirRace, when set (tests), runs between the removal of another
// account's directory and lox making it again: where an engine restarting
// the old hub could make it again first.
var facadeDirRace func(d string)

// readyFacadeDir makes d, the directory of the hub's facade socket
// ($XDG_RUNTIME_DIR/lockhub, bind-mounted in the hub), the user's with mode
// 0700, before anything starts. That directory lives on a tmpfs wiped at
// logout and reboot, and a Docker engine that restarted the hub on its own
// while it was missing made it as root, mode 0755: the hub refuses it.
//
// Its parent (the runtime directory) must be the user's, not a link, and
// writable by no one else: otherwise (XDG_RUNTIME_DIR unset, the fallback
// under the shared temporary directory made by another account) nothing is
// made or removed there. A missing parent is made (0700).
//
// Missing: it is made. The user's with another mode: it is closed (0700).
// Another account's and empty: it is removed and made again. Anything else
// (a link, a file, another account's directory that holds something or
// that lox cannot remove) is left as it is, and the error names the
// commands to run. mine says whether a file is the user's.
//
// made is true when the directory was made or repaired: a hub created
// before still binds the old one, and must be created again. The note says
// what was repaired ("" when nothing was, or the directory was missing).
func readyFacadeDir(d string, mine func(os.FileInfo) bool) (made bool, note string, err error) {
	if err := runtimeParent(filepath.Dir(d), mine); err != nil {
		return false, "", err
	}
	return readyFacadeDirTry(d, mine, true)
}

// runtimeParent makes p (0700) if it is missing, and refuses it unless it
// is a directory (not a link) of the user's that group and others cannot
// write.
func runtimeParent(p string, mine func(os.FileInfo) bool) error {
	fi, err := os.Lstat(p)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(p, 0o700); err != nil {
			return err
		}
		fi, err = os.Lstat(p)
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() || !mine(fi) || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("runtime directory %s (the facade directory's parent) is not a directory of yours that only you can write (uid %d, mode %v): lox makes and removes nothing there. "+
			"Set XDG_RUNTIME_DIR to a directory of yours with mode 0700 (systemd's /run/user/$(id -u)), then lox run again", p, owner(fi), fi.Mode())
	}
	return nil
}

func readyFacadeDirTry(d string, mine func(os.FileInfo) bool, retry bool) (bool, string, error) {
	fi, err := os.Lstat(d)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(d, 0o700); err != nil {
			return false, "", err
		}
		return true, "", checkPrivateAs(d, mine)
	}
	if err != nil {
		return false, "", err
	}
	if checkPrivateAs(d, mine) == nil {
		return false, "", nil
	}
	if !fi.IsDir() {
		sudo := ""
		if !mine(fi) {
			sudo = "sudo "
		}
		return false, "", fmt.Errorf("facade directory %s: not a directory (a link?): check what it is (ls -la %s), remove it (%srm %s), then lox run again", d, d, sudo, d)
	}
	was := fmt.Sprintf("uid %d, mode %04o", owner(fi), fi.Mode().Perm())
	if mine(fi) {
		if err := os.Chmod(d, 0o700); err != nil {
			return false, "", err
		}
		return true, fmt.Sprintf("facade directory %s: mode 0700 (it was %04o)", d, fi.Mode().Perm()), checkPrivateAs(d, mine)
	}
	// Another account's: a directory lox can only remove when empty
	// (rmdir), and never empties.
	entries, rerr := os.ReadDir(d)
	if rerr == nil && len(entries) > 0 {
		return false, "", fmt.Errorf("facade directory %s is not yours (%s) and is not empty, so lox leaves it: check what it holds (sudo ls -la %s), then run\n  sudo rm -r %s && mkdir -m 700 %s\nand lox run again", d, was, d, d, d)
	}
	if err := os.Remove(d); err != nil {
		return false, "", fmt.Errorf("facade directory %s is not yours (%s; Docker makes a missing bind source as root) and lox cannot remove it (%v): run\n  sudo rmdir %s && mkdir -m 700 %s\nthen lox run again", d, was, err, d, d)
	}
	if facadeDirRace != nil {
		facadeDirRace(d)
	}
	if err := os.Mkdir(d, 0o700); errors.Is(err, os.ErrExist) {
		// Made again meanwhile (the old hub restarted by its engine): once
		// more, then give up.
		if retry {
			return readyFacadeDirTry(d, mine, false)
		}
		return false, "", fmt.Errorf("facade directory %s was made again by someone else (a hub its engine restarted?) while lox repaired it: run lox run again", d)
	} else if err != nil {
		return false, "", err
	}
	if err := checkPrivateAs(d, mine); err != nil {
		return false, "", err
	}
	return true, fmt.Sprintf("facade directory %s: made again, yours, mode 0700 (it was %s, empty)", d, was), nil
}
