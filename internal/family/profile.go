package family

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// A lock's own profile directory is in the workspace, which lea's agents
// can write. lock up never mounts it: it reads it once (no link
// followed, only the user's own regular files and directories), shows its
// fingerprint in the review, and after the human's yes copies exactly
// what was reviewed into the volume profile-<type> (written by root,
// read-only in the lock).

// maxProfile bounds a profile directory's content (it reaches the setup
// service as one argument).
const maxProfile = 64 << 10

// Profile is the reviewed copy of a lock's profile directory.
type Profile struct {
	// Tar is the directory as a deterministic tar archive.
	Tar []byte
	// Fingerprint is the sha256 of Tar.
	Fingerprint string
}

// ReadProfile snapshots the directory dir.
func ReadProfile(dir string) (*Profile, error) {
	if err := ownDir(dir); err != nil {
		return nil, err
	}
	var paths []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p != dir {
			paths = append(paths, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	total := 0
	for _, p := range paths {
		rel, _ := filepath.Rel(dir, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		switch {
		case fi.IsDir():
			if err := ownDir(p); err != nil {
				return nil, err
			}
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: filepath.ToSlash(rel) + "/", Mode: 0o755}); err != nil {
				return nil, err
			}
		case fi.Mode().IsRegular():
			b, err := readOwnFile(p, fi)
			if err != nil {
				return nil, err
			}
			if total += len(b); total > maxProfile {
				return nil, fmt.Errorf("%s: more than %d bytes", dir, maxProfile)
			}
			if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: filepath.ToSlash(rel), Mode: 0o644, Size: int64(len(b))}); err != nil {
				return nil, err
			}
			tw.Write(b)
		default:
			return nil, fmt.Errorf("%s: not a regular file or a directory (a link?): lock up copies none", p)
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	s := sha256.Sum256(buf.Bytes())
	return &Profile{Tar: buf.Bytes(), Fingerprint: "sha256:" + hex.EncodeToString(s[:])}, nil
}

// B64 is the archive as the setup service takes it.
func (p *Profile) B64() string { return base64.StdEncoding.EncodeToString(p.Tar) }

// ownDir refuses d unless it is a directory (not a link) of this user
// that no one else can write.
func ownDir(d string) error {
	fi, err := os.Lstat(d)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s: not a directory (a link?)", d)
	}
	return ownedNotShared(d, fi)
}

func ownedNotShared(p string, fi os.FileInfo) error {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s: owned by uid %d, not by you", p, st.Uid)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: mode %v: writable by others than you", p, fi.Mode().Perm())
	}
	return nil
}

// readOwnFile reads the regular file p without following a link, and
// only if it is still the file fi described.
func readOwnFile(p string, fi os.FileInfo) ([]byte, error) {
	if err := ownedNotShared(p, fi); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	got, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(fi, got) || !got.Mode().IsRegular() {
		return nil, fmt.Errorf("%s changed while lock up read it", p)
	}
	return io.ReadAll(io.LimitReader(f, maxProfile+1))
}
