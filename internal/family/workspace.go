package family

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// CheckWorkspace refuses a workspace someone else than the user could
// change: the workspace directory, its .lockfamily/ and every lock's
// .<type>/ (those that exist) must be directories (not links) of the
// user's that group and others cannot write. A member of the group could
// otherwise replace a lock's reviewed configuration between two lox runs,
// and lox add would write into a directory others control. One check, one
// message, for every lock type.
//
// The workspace may be reached through a link: its real directory is
// checked.
func CheckWorkspace(ws string) error {
	if real, err := filepath.EvalSymlinks(ws); err == nil {
		ws = real
	}
	dirs := []string{ws, filepath.Join(ws, Dir)}
	for _, t := range Types {
		dirs = append(dirs, profileDir(ws, t))
	}
	for i, d := range dirs {
		fi, err := os.Lstat(d)
		if i > 0 && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("workspace %s: %w", ws, err)
		}
		if err := ownedPrivate(d, fi); err != nil {
			return err
		}
	}
	return nil
}

// ownedPrivate is CheckWorkspace's verdict on one directory, with what to
// run to fix it.
func ownedPrivate(d string, fi os.FileInfo) error {
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory (a symbolic link or a file): the workspace's configuration must be directories of your own; remove it and retry", d)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not by you: use a workspace directory of your own", d, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by someone else than you (mode %04o): someone could replace a lock's reviewed configuration; run chmod go-w %s and retry", d, fi.Mode().Perm(), d)
	}
	return nil
}
