package loxadd

import (
	"slices"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// The compose service first, then the database or vhost, else the
// lock's usual name; never hub.
func TestSuggestName(t *testing.T) {
	for _, c := range []struct {
		s    loxinit.Source
		want string
	}{
		{shopDB, "db"},
		{shopMQ, "mq"},
		{inventory, "stock"},
		{loxinit.Source{Kind: loxinit.KindPostgres, Database: "Orders_2026"}, "orders-2026"},
		{loxinit.Source{Kind: loxinit.KindPostgres, Service: "hub"}, "hub-db"},
		{loxinit.Source{Kind: loxinit.KindPostgres, Database: strings.Repeat("a", 39) + "-b"}, strings.Repeat("a", 39)},
		{loxinit.Source{Kind: loxinit.KindRabbitMQ}, "mq"},
		{loxinit.Source{Kind: loxinit.KindMySQL, Database: "--"}, "db"},
	} {
		if got := SuggestName(c.s); got != c.want {
			t.Errorf("SuggestName(%+v) = %q, want %q", c.s, got, c.want)
		}
	}
}

func TestUniqueName(t *testing.T) {
	taken := func(n string) bool { return n == "db" || n == "db-2" }
	for name, want := range map[string]string{"db": "db-3", "orders": "orders"} {
		if got := uniqueName(name, taken); got != want {
			t.Errorf("uniqueName(%q) = %q, want %q", name, got, want)
		}
	}
}

// lea's uid, for the locks lea's agents reach, when a console takes it.
func TestUIDsFor(t *testing.T) {
	for _, c := range []struct {
		lock string
		lea  bool
		uid  int
		want []int
	}{
		{"locksql", true, 1000, []int{1000}},
		{"lockmq", true, 1000, []int{1000}},
		{"lockfile", true, 1000, []int{1000}},
		{"lockhttp", true, 1000, nil},
		{"locksql", false, 1000, nil},
		{"locksql", true, 0, nil},
		{"locksql", true, 65534, nil},
	} {
		if got := uidsFor(c.lock, c.lea, c.uid); !slices.Equal(got, c.want) {
			t.Errorf("uidsFor(%s, %v, %d) = %v, want %v", c.lock, c.lea, c.uid, got, c.want)
		}
	}
}

// A value that embeds a password, or holds a control character, never
// goes on a command line; the reason never quotes it.
func TestUnsafeValue(t *testing.T) {
	const secret = "Sup3r-s3cret-value-9f2c"
	for v, want := range map[string]string{
		"http://u:" + secret + "@host.docker.internal:15672": "it embeds a password",
		"host=db password=" + secret:                         "it embeds a password",
		"Server=db;Pwd=" + secret:                            "it embeds a password",
		"shop\n":                                             "a control character",
		"http://ro@host.docker.internal:15672":               "",
		"host.docker.internal":                               "",
	} {
		got := unsafeValue(v)
		if got != want {
			t.Errorf("unsafeValue(%q) = %q, want %q", v, got, want)
		}
		if strings.Contains(got, secret) {
			t.Errorf("the reason quotes the value: %q", got)
		}
	}
}
