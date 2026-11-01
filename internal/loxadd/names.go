package loxadd

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

var nameChars = regexp.MustCompile(`[^a-z0-9-]+`)

// cleanName is s made an instance and profile name: lower case, digits
// and -, at most 40 characters; "" when nothing is left.
func cleanName(s string) string {
	n := nameChars.ReplaceAllString(strings.ToLower(s), "-")
	n = strings.Trim(n, "-")
	if len(n) > 40 {
		n = strings.Trim(n[:40], "-")
	}
	if n == "hub" {
		n = "hub-db"
	}
	return n
}

// SuggestName is the instance (and profile) name proposed for s: its
// compose service, its database or vhost, else the lock's usual one.
func SuggestName(s loxinit.Source) string {
	for _, c := range []string{s.Service, s.Database, s.VHost} {
		if n := cleanName(c); n != "" {
			return n
		}
	}
	if s.Kind == loxinit.KindRabbitMQ {
		return "mq"
	}
	return "db"
}

// uniqueName is name, or name-2, name-3... when an instance (declared
// or planned) already has it.
func uniqueName(name string, taken func(string) bool) string {
	if !taken(name) {
		return name
	}
	for i := 2; ; i++ {
		n := fmt.Sprintf("%s-%d", name, i)
		if !taken(n) {
			return n
		}
	}
}

// UIDsFor are lox up's allowed_uids of a lock lea's agents reach: lea's
// uid, when it is one a console takes (not root, not nobody).
func UIDsFor(lock string, lea bool, uid int) []int {
	if !lea || uid <= 0 || uid == 65534 || !slices.Contains([]string{"locksql", "lockmq", "lockfile"}, lock) {
		return nil
	}
	return []int{uid}
}

// unsafeValue says why v cannot go on a command line ("" when it can).
func unsafeValue(v string) string {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return "a control character"
		}
	}
	if u, err := url.Parse(v); err == nil && u.User != nil {
		if _, ok := u.User.Password(); ok {
			return "it embeds a password"
		}
	}
	l := strings.ToLower(v)
	if strings.Contains(l, "password=") || strings.Contains(l, "pwd=") {
		return "it embeds a password"
	}
	return ""
}
