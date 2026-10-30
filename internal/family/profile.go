package family

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unicode/utf8"
)

// A lock's own profile directory is in the workspace, which lea's agents
// can write. lock up never mounts it: it reads it once (no link
// followed, only the user's own regular files and directories), shows its
// fingerprint in the review, and after the human's yes copies exactly
// what was reviewed into the volume profile-<type> (written by root,
// read-only in the lock), on the setup service's stdin, never in an
// argument (profiles can hold secrets; arguments are public).

// maxProfile bounds a profile directory's content.
const maxProfile = 256 << 10

// Profile is the reviewed copy of a lock's profile directory.
type Profile struct {
	// Tar is the directory as a deterministic tar archive.
	Tar []byte
	// Fingerprint is the sha256 of Tar.
	Fingerprint string
	// Files are the regular files' names (slash-separated).
	Files []string
	// Lines are what the human reviews: each file by name, size and
	// hash, and the lines of its TOML files (lockkit's configuration
	// refuses secrets in them).
	Lines []string
}

// maxTOML bounds a TOML file of a profile (all its lines are shown).
const maxTOML = 64 << 10

// maxEntries bounds a profile directory's files and directories.
const maxEntries = 256

// ReadProfile snapshots the directory dir. It opens dir once, without
// following a link, and reads below it through that handle only
// (os.Root: no path, even one swapped for a link while it is read,
// leads outside dir); every file and directory is checked on the handle
// it was read through.
//
// The copy is owned by uid:gid (the console's account), with the
// owner-only modes kept: a 0600 file stays 0600 (locks refuse a key
// others can read).
func ReadProfile(dir string, uid, gid int) (*Profile, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s: not a directory (a link?)", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	r := &profileReader{root: root, dir: dir, tw: tw, uid: uid, gid: gid}
	// The root itself: still the directory checked above.
	if err := r.walk(".", fi); err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if buf.Len() > maxTar {
		return nil, fmt.Errorf("%s: more than %d bytes", dir, maxProfile)
	}
	s := sha256.Sum256(buf.Bytes())
	return &Profile{Tar: buf.Bytes(), Fingerprint: "sha256:" + hex.EncodeToString(s[:]), Lines: r.lines, Files: r.files}, nil
}

// maxTar bounds the archive (maxProfile of content plus the headers).
const maxTar = maxProfile + (maxEntries+2)*1024

type profileReader struct {
	root     *os.Root
	dir      string
	tw       *tar.Writer
	total    int
	entries  int
	uid, gid int
	lines    []string
	files    []string
}

// Has reports a file under dir (prefix) with the suffix.
func (p *Profile) Has(prefix, suffix string) bool {
	for _, f := range p.Files {
		if strings.HasPrefix(f, prefix) && strings.HasSuffix(f, suffix) {
			return true
		}
	}
	return false
}

// mode is the copy's mode: owner-only stays owner-only.
func mode(fi os.FileInfo, open int64) int64 {
	if fi.Mode().Perm()&0o077 == 0 {
		return open &^ 0o077
	}
	return open
}

// walk adds the directory rel, which lstat described as want.
func (r *profileReader) walk(rel string, want os.FileInfo) error {
	d, err := r.root.Open(rel)
	if err != nil {
		return err
	}
	defer d.Close()
	fi, err := d.Stat()
	if err != nil {
		return err
	}
	name := filepath.Join(r.dir, rel)
	if !fi.IsDir() || !os.SameFile(fi, want) {
		return fmt.Errorf("%s changed while lock up read it", name)
	}
	if err := ownedNotShared(name, fi); err != nil {
		return err
	}
	if rel != "." {
		if err := r.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeDir, Name: filepath.ToSlash(rel) + "/", Mode: mode(fi, 0o755), Uid: r.uid, Gid: r.gid}); err != nil {
			return err
		}
	}
	ents, err := d.ReadDir(-1)
	if err != nil {
		return err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	for _, e := range ents {
		if r.entries++; r.entries > maxEntries {
			return fmt.Errorf("%s: more than %d entries", r.dir, maxEntries)
		}
		// Names reach the human's review: printable ones only.
		if !plainName(e.Name()) {
			return fmt.Errorf("%s: a file name with control, invisible or bidirectional characters (%q): lock up copies none", r.dir, e.Name())
		}
		crel := filepath.Join(rel, e.Name())
		cfi, err := r.root.Lstat(crel)
		if err != nil {
			return err
		}
		switch {
		case cfi.IsDir():
			if err := r.walk(crel, cfi); err != nil {
				return err
			}
		case cfi.Mode().IsRegular():
			if err := r.file(crel, cfi); err != nil {
				return err
			}
		default:
			return fmt.Errorf("%s: not a regular file or a directory (a link?): lock up copies none", filepath.Join(r.dir, crel))
		}
	}
	return nil
}

// file adds the regular file rel, which lstat described as want.
func (r *profileReader) file(rel string, want os.FileInfo) error {
	name := filepath.Join(r.dir, rel)
	f, err := r.root.OpenFile(rel, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() || !os.SameFile(fi, want) {
		return fmt.Errorf("%s changed while lock up read it", name)
	}
	if err := ownedNotShared(name, fi); err != nil {
		return err
	}
	b, err := io.ReadAll(io.LimitReader(f, maxProfile+1))
	if err != nil {
		return err
	}
	if r.total += len(b); r.total > maxProfile {
		return fmt.Errorf("%s: more than %d bytes", r.dir, maxProfile)
	}
	if err := r.tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: filepath.ToSlash(rel), Mode: mode(fi, 0o644), Size: int64(len(b)), Uid: r.uid, Gid: r.gid}); err != nil {
		return err
	}
	r.files = append(r.files, filepath.ToSlash(rel))
	h := sha256.Sum256(b)
	r.lines = append(r.lines, fmt.Sprintf("file %s %d bytes sha256:%s", filepath.ToSlash(rel), len(b), hex.EncodeToString(h[:])))
	if strings.HasSuffix(rel, ".toml") {
		// Every line of a configuration is reviewed: none too big or not
		// text to show.
		if !utf8.Valid(b) || len(b) > maxTOML {
			return fmt.Errorf("%s: a TOML file must be UTF-8 text of at most %d bytes, every line of it is reviewed", name, maxTOML)
		}
		for i, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
			r.lines = append(r.lines, fmt.Sprintf("%s:%d %s", filepath.ToSlash(rel), i+1, printable(l)))
		}
	}
	_, err = r.tw.Write(b)
	return err
}

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
		return fmt.Errorf("%s: mode %04o: writable by others than you", p, fi.Mode().Perm())
	}
	return nil
}

// hidden are the characters that would change what the human sees:
// controls, zero-width and bidirectional marks.
func hidden(c rune) bool {
	return c < 0x20 || c == 0x7f || (c >= 0x80 && c < 0xa0) || (c >= 0x200b && c <= 0x200f) ||
		(c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c == 0xfeff
}

func plainName(n string) bool {
	if !utf8.ValidString(n) {
		return false
	}
	for _, c := range n {
		if hidden(c) {
			return false
		}
	}
	return true
}

// printable is l with hidden characters shown as \x{NN} (no escape
// sequence, no reordering reaches the human's terminal).
func printable(l string) string {
	var b strings.Builder
	for _, c := range l {
		if c != '\t' && hidden(c) {
			fmt.Fprintf(&b, "\\x{%x}", c)
			continue
		}
		b.WriteRune(c)
	}
	return b.String()
}
