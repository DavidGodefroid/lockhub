package family

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// LockfileSeccomp is the seccomp profile lockfile ships (seccomp.json at
// its repository's root, in every release tarball beside its launcher):
// lockfile's own launcher runs every console container under it and
// refuses to start one without it. The image does not carry it, so lox run
// carries this byte-for-byte copy (unchanged from lockfile v0.3.0 to
// v0.7.0, every release lox add pins) and runs each lockfile lock under it
// instead of Docker's default, which varies with the engine's version.
// When lockfile changes its seccomp.json, copy it here: the test pins its
// digest so the change is deliberate and reviewed (each lockfile lock's
// summary line shows the new digest at the next lox run).
//
//go:embed lockfile-seccomp.json
var LockfileSeccomp []byte

// LockfileSeccompSum is the sha256 (hex) of LockfileSeccomp.
var LockfileSeccompSum = func() string {
	s := sha256.Sum256(LockfileSeccomp)
	return hex.EncodeToString(s[:])
}()

// lockfileSeccompFile is the copy of LockfileSeccomp lox run writes in the
// workspace's state directory, which compose reads when it creates a
// lockfile console (the engine gets the profile's content, not the path).
const lockfileSeccompFile = "lockfile-seccomp.json"

// usesSeccomp tells whether a lock of type typ runs under LockfileSeccomp.
func usesSeccomp(typ string) bool { return typ == "lockfile" }

// hasSeccompLock tells whether c runs a lock under LockfileSeccomp.
func (c *Config) hasSeccompLock() bool {
	for _, l := range c.Locks {
		if usesSeccomp(l.Type) {
			return true
		}
	}
	return false
}
