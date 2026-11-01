package loxadd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fieldsOf(t *testing.T, lock string, d Defaults) []Field {
	t.Helper()
	fs, err := Fields(lock, d)
	if err != nil {
		t.Fatalf("Fields(%s): %v", lock, err)
	}
	return fs
}

// find is the field of key whose When accepts a (the first one, when a is nil).
func find(t *testing.T, fs []Field, key string, a Answers) Field {
	t.Helper()
	for _, f := range fs {
		if f.Key == key && (a == nil || f.When == nil || f.When(a)) {
			return f
		}
	}
	t.Fatalf("no field %q for %v", key, a)
	return Field{}
}

func TestFieldsUnknownLock(t *testing.T) {
	if _, err := Fields("lockfoo", Defaults{}); err == nil {
		t.Fatal("Fields accepted an unknown lock")
	}
}

func TestPromptMarkers(t *testing.T) {
	for _, lock := range []string{"locksql", "lockmq", "lockfile", "lockhttp"} {
		for _, d := range []Defaults{{}, {Source: &shopDB}, {Source: &shopMQ}} {
			for _, f := range fieldsOf(t, lock, d) {
				p := Prompt(f)
				if f.YesNo {
					if !strings.HasSuffix(p, "[y/N] ") && !strings.HasSuffix(p, "[Y/n] ") {
						t.Errorf("%s %s: yes/no prompt %q shows no default", lock, f.Key, p)
					}
					continue
				}
				if !strings.HasSuffix(p, ": ") {
					t.Errorf("%s %s: prompt %q does not end with a colon", lock, f.Key, p)
				}
				if f.Empty == "" {
					if !strings.Contains(p, " (required)") || strings.Contains(p, "optional") {
						t.Errorf("%s %s: %q wants (required) only", lock, f.Key, p)
					}
				} else if f.Default != "" {
					if !strings.Contains(p, " (optional: - = "+f.Empty+")") || strings.Contains(p, "(required)") {
						t.Errorf("%s %s: %q wants the optional marker with a default", lock, f.Key, p)
					}
				} else if !strings.Contains(p, " (optional: empty = "+f.Empty+")") || strings.Contains(p, "(required)") {
					t.Errorf("%s %s: %q wants the optional marker", lock, f.Key, p)
				}
				if f.Default != "" && !strings.HasSuffix(p, " ["+f.Default+"]: ") {
					t.Errorf("%s %s: %q does not show its default %q", lock, f.Key, p, f.Default)
				}
			}
		}
	}
}

func TestPromptsVerbatim(t *testing.T) {
	sql := fieldsOf(t, "locksql", Defaults{})
	pg := Answers{"engine": "postgres", "host": "host.docker.internal"}
	for key, want := range map[string]string{
		"engine":   "Engine: postgres, mysql, mariadb or sqlite (required) [postgres]: ",
		"host":     "Host (required) [host.docker.internal]: ",
		"port":     "Port (required) [5432]: ",
		"user":     "User (optional: empty = the console asks for it at start with the password): ",
		"database": "Database (optional: empty = the server's default database): ",
		"tls":      "TLS: disable, prefer, require, verify-ca or verify-full (required) [disable]: ",
		"name":     "Name (required) [db]: ",
	} {
		if got := Prompt(find(t, sql, key, pg)); got != want {
			t.Errorf("%s: %q, want %q", key, got, want)
		}
	}
	if got := Prompt(find(t, sql, "credentials", pg)); got != "Credentials: ask (typed, masked, at the console's start) or vault (required) [ask]: " {
		t.Errorf("credentials: %q", got)
	}
	if got := Prompt(find(t, sql, "vault-path", Answers{"engine": "postgres", "credentials": "vault"})); got != "Vault path (required) [database/creds/db]: " {
		t.Errorf("vault path: %q", got)
	}
	if got := Prompt(find(t, sql, "path", Answers{"engine": "sqlite"})); got != "Path (required): " {
		t.Errorf("sqlite path: %q", got)
	}
	mq := fieldsOf(t, "lockmq", Defaults{})
	for key, want := range map[string]string{
		"url":        "Management URL (required) [http://host.docker.internal:15672]: ",
		"vhost":      "Vhost (optional: empty = all vhosts the user can see): ",
		"amqp-url":   "AMQP URL, such as amqp://<mgmt host>:5672 (optional: empty = no stream reads): ",
		"name":       "Name (required) [mq]: ",
		"vault-path": "Vault path (required) [rabbitmq/creds/mq]: ",
	} {
		if got := Prompt(find(t, mq, key, Answers{"credentials": "vault"})); got != want {
			t.Errorf("mq %s: %q, want %q", key, got, want)
		}
	}
	web := fieldsOf(t, "lockhttp", Defaults{})
	if len(web) != 1 || Prompt(web[0]) != "Name (required) [web]: " {
		t.Errorf("lockhttp: %+v", web)
	}
	v := Answers{"credentials": "vault"}
	for key, want := range map[string]string{
		"vault-address":   "Vault address, such as https://vault.example.com:8200 (required): ",
		"vault-namespace": "Vault namespace (optional: empty = the root namespace): ",
		"vault-ca":        "Vault CA file (optional: empty = the system's CA certificates): ",
	} {
		if got := Prompt(find(t, mq, key, v)); got != want {
			t.Errorf("%s: %q, want %q", key, got, want)
		}
	}
}

func TestProductionPromptVerbatim(t *testing.T) {
	const want = "Production? (each approval needs the profile name typed) [y/N] "
	for _, lock := range []string{"locksql", "lockmq", "lockfile"} {
		if got := Prompt(find(t, fieldsOf(t, lock, Defaults{}), "production", nil)); got != want {
			t.Errorf("%s: %q, want %q", lock, got, want)
		}
	}
	for _, f := range fieldsOf(t, "lockhttp", Defaults{}) {
		if f.Key == "production" {
			t.Error("lockhttp asks Production")
		}
	}
}

func TestVaultBlockOnlyForTheFirstVaultLock(t *testing.T) {
	has := func(d Defaults) bool {
		for _, f := range fieldsOf(t, "lockmq", d) {
			if f.Key == "vault-address" {
				return true
			}
		}
		return false
	}
	if !has(Defaults{}) || has(Defaults{VaultSet: true}) {
		t.Error("the vault block is asked iff the vault is not set yet")
	}
}

func TestSQLiteAsksPathOnly(t *testing.T) {
	a := Answers{"engine": "sqlite", "credentials": "ask"}
	var keys []string
	for _, f := range fieldsOf(t, "locksql", Defaults{}) {
		if f.When == nil || f.When(a) {
			keys = append(keys, f.Key)
		}
	}
	if got := strings.Join(keys, " "); got != "engine path production name" {
		t.Errorf("sqlite asks %q", got)
	}
}

func TestDefaultsFromDetection(t *testing.T) {
	pg := Answers{"engine": "postgres"}
	fs := fieldsOf(t, "locksql", Defaults{Source: &shopDB, Declared: []string{"other"}})
	for key, want := range map[string]string{"engine": "postgres", "host": "host.docker.internal", "port": "55432", "user": "shop", "database": "shop", "tls": "disable", "name": "db"} {
		if got := find(t, fs, key, pg).Default; got != want {
			t.Errorf("%s default %q, want %q", key, got, want)
		}
	}
	if got := find(t, fs, "vault-path", Answers{"engine": "postgres", "credentials": "vault"}).Default; got != "database/creds/db" {
		t.Errorf("vault path default %q", got)
	}
	// A name already declared moves the suggestion on.
	fs = fieldsOf(t, "locksql", Defaults{Source: &shopDB, Declared: []string{"db"}})
	if got := find(t, fs, "name", pg).Default; got != "db-2" {
		t.Errorf("name default %q, want db-2", got)
	}
	// A remote database proposes verify-full.
	fs = fieldsOf(t, "locksql", Defaults{Source: &inventory})
	if got := find(t, fs, "tls", Answers{"engine": "mysql"}).Default; got != "verify-full" {
		t.Errorf("remote tls default %q", got)
	}
	if got := find(t, fs, "port", Answers{"engine": "mysql"}).Default; got != "3307" {
		t.Errorf("mysql port default %q", got)
	}
	// Without detection the port follows the engine.
	fs = fieldsOf(t, "locksql", Defaults{})
	if got := find(t, fs, "port", Answers{"engine": "mariadb"}).Default; got != "3306" {
		t.Errorf("mariadb port default %q", got)
	}
	mq := fieldsOf(t, "lockmq", Defaults{Source: &shopMQ})
	for key, want := range map[string]string{"url": "http://host.docker.internal:55672", "user": "orders", "vhost": "orders", "amqp-url": "amqp://host.docker.internal:55673", "name": "mq"} {
		if got := find(t, mq, key, nil).Default; got != want {
			t.Errorf("mq %s default %q, want %q", key, got, want)
		}
	}
	// A draft answer is the default again.
	fs = fieldsOf(t, "locksql", Defaults{Source: &shopDB, Draft: Answers{"host": "db.example.com"}})
	if got := find(t, fs, "host", pg).Default; got != "db.example.com" {
		t.Errorf("draft host default %q", got)
	}
}

func TestChecks(t *testing.T) {
	sql := fieldsOf(t, "locksql", Defaults{Declared: []string{"orders"}})
	pg := Answers{"engine": "postgres"}
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	mq := fieldsOf(t, "lockmq", Defaults{})
	fl := fieldsOf(t, "lockfile", Defaults{})
	for _, c := range []struct {
		fs   []Field
		key  string
		a    Answers
		v    string
		want string // "" = accepted, else a part of the reason
	}{
		{sql, "port", pg, "5432", ""},
		{sql, "port", pg, "0", "port: want a number from 1 to 65535"},
		{sql, "port", pg, "65536", "port: want a number from 1 to 65535"},
		{sql, "port", pg, "abc", "port: want a number from 1 to 65535"},
		{sql, "host", pg, "db.example.com", ""},
		{sql, "host", pg, "::1", ""},
		{sql, "host", pg, "db.example.com:5432", "host: a host name or address, without a port or scheme"},
		{sql, "host", pg, "postgres://db.example.com", "host: a host name or address, without a port or scheme"},
		{sql, "host", pg, "", "host:"},
		{sql, "user", pg, "shop", ""},
		{sql, "user", pg, "", ""},
		{sql, "database", pg, "password=hunter2pw", "database: it embeds a password: type the target without it (the console asks for the password at its start)"},
		{sql, "name", pg, "shop-db", ""},
		{sql, "name", pg, "Shop_DB", "name: lower case letters, digits and -, at most 40 characters"},
		{sql, "name", pg, strings.Repeat("a", 41), "name: lower case letters, digits and -, at most 40 characters"},
		{sql, "name", pg, "orders", "name: a lock named orders is declared already"},
		{sql, "credentials", pg, "vault", ""},
		{sql, "credentials", pg, "typed", "credentials: want ask or vault"},
		{sql, "engine", nil, "sqlite", ""},
		{sql, "engine", nil, "oracle", "engine: want postgres, mysql, mariadb or sqlite"},
		{sql, "tls", pg, "verify-full", ""},
		{sql, "tls", pg, "on", "tls:"},
		{sql, "production", nil, "y", ""},
		{sql, "production", nil, "maybe", "production:"},
		{mq, "url", nil, "https://mq.example.com:15671", ""},
		{mq, "url", nil, "mq.example.com", "url:"},
		{mq, "url", nil, "http://guest:hunter2pw@mq.example.com", "url: it embeds a password: type the target without it"},
		{mq, "amqp-url", nil, "amqp://mq.example.com:5672", ""},
		{mq, "amqp-url", nil, "amqp://u:hunter2pw@mq.example.com:5672", "amqp-url: it embeds a password"},
		{mq, "amqp-url", nil, "http://mq.example.com", "amqp-url:"},
		{mq, "vault-address", Answers{"credentials": "vault"}, "https://vault.example.com:8200", ""},
		{mq, "vault-address", Answers{"credentials": "vault"}, "vault.example.com", "vault-address:"},
		{mq, "vault-ca", Answers{"credentials": "vault"}, file, ""},
		{mq, "vault-ca", Answers{"credentials": "vault"}, "ca.pem", "vault-ca:"},
		{mq, "vault-ca", Answers{"credentials": "vault"}, filepath.Dir(file), "vault-ca:"},
		{fl, "bucket", Answers{"source": "s3"}, "shop-invoices", ""},
		{fl, "bucket", Answers{"source": "s3"}, "https://s3.example.com/shop", "bucket: a bucket name, not a URL (such as shop-invoices)"},
		{fl, "bucket", Answers{"source": "s3"}, "s3://shop", "bucket: a bucket name, not a URL (such as shop-invoices)"},
		{fl, "endpoint", Answers{"source": "s3"}, "https://minio.example.com:9000", ""},
		{fl, "endpoint", Answers{"source": "s3"}, "minio.example.com:9000", "endpoint: a URL with its scheme, such as https://minio.example.com:9000"},
		{fl, "endpoint", Answers{"source": "s3"}, "", ""},
		{fl, "path", Answers{"source": "local"}, "/srv/shop/files", ""},
		{fl, "path", Answers{"source": "local"}, "files", "path:"},
		{fl, "source", nil, "ftp", "source:"},
	} {
		f := find(t, c.fs, c.key, c.a)
		got := f.Check(c.v, c.a)
		if c.want == "" && got != "" || c.want != "" && !strings.Contains(got, c.want) {
			t.Errorf("%s %q: %q, want %q", c.key, c.v, got, c.want)
		}
		if strings.Contains(got, "hunter2pw") {
			t.Errorf("%s: the reason %q echoes the value", c.key, got)
		}
	}
}

func TestLockfileSFTPQuestions(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	const secretBody = "-----BEGIN PRIVATE KEY-----sekret"
	if err := os.WriteFile(key, []byte(secretBody), 0o600); err != nil {
		t.Fatal(err)
	}
	fs := fieldsOf(t, "lockfile", Defaults{})
	if got := Prompt(find(t, fs, "source", nil)); got != "Source: local, s3 or sftp (required) [s3]: " {
		t.Errorf("source prompt %q", got)
	}
	a := Answers{"source": "sftp", "auth": "key", "credentials": "ask"}
	var keys []string
	for _, f := range fs {
		if f.When == nil || f.When(a) {
			keys = append(keys, f.Key)
		}
	}
	if got := strings.Join(keys, " "); got != "source host port user auth key known-hosts base-dir production credentials name" {
		t.Errorf("sftp asks %q", got)
	}
	for key, want := range map[string]string{
		"host":        "Host (required): ",
		"port":        "Port (required) [22]: ",
		"user":        "User (required): ",
		"auth":        "Auth: key or password (required) [key]: ",
		"key":         "Private key file, an absolute path (required): ",
		"known-hosts": "Known hosts file (required): ",
		"base-dir":    "Base directory (optional: empty = the login directory): ",
	} {
		if got := Prompt(find(t, fs, key, a)); got != want {
			t.Errorf("%s: %q, want %q", key, got, want)
		}
	}
	if got := Prompt(find(t, fs, "vault-path", Answers{"source": "sftp", "credentials": "vault"})); got != "Vault path (required) [secret/data/lockfile/files]: " {
		t.Errorf("vault path %q", got)
	}
	k := find(t, fs, "key", a)
	if got := k.Check(key, a); got != "" {
		t.Errorf("key file refused: %q", got)
	}
	for _, v := range []string{"", "id_ed25519", dir, filepath.Join(dir, "missing")} {
		got := k.Check(v, a)
		if got == "" || !strings.HasPrefix(got, "key:") || strings.Contains(got, secretBody) {
			t.Errorf("key %q: %q", v, got)
		}
	}
	kh := find(t, fs, "known-hosts", a)
	if kh.Empty != "" || kh.Check("", a) == "" {
		t.Error("known_hosts must be required")
	}
	pw := Answers{"source": "sftp", "auth": "password"}
	for _, f := range fs {
		if f.Key == "key" && f.When(pw) {
			t.Error("a key file is asked for password auth")
		}
	}
	if kh.Check("known_hosts", a) == "" {
		t.Error("a relative known_hosts path was accepted")
	}
	// Local reads no secret: no credentials question; s3 asks one.
	c := find(t, fs, "credentials", Answers{"source": "s3"})
	for src, want := range map[string]bool{"local": false, "s3": true, "sftp": true} {
		if got := c.When(Answers{"source": src}); got != want {
			t.Errorf("credentials asked for %s: %v", src, got)
		}
	}
	// The key's content is never in an answer or a prompt.
	for _, f := range fs {
		if strings.Contains(Prompt(f), "sekret") {
			t.Fatal("prompt leaks")
		}
	}
}

func TestTLSDefaultFollowsTheHost(t *testing.T) {
	fs := fieldsOf(t, "locksql", Defaults{})
	for _, c := range []struct {
		host, prod, want string
	}{
		{"db.example.com", "n", "verify-full"},
		{"host.docker.internal", "n", "disable"},
		{"localhost", "", "disable"},
		{"127.0.0.1", "n", "disable"},
		{"::1", "n", "disable"},
		{"host.docker.internal", "y", "verify-full"},
		{"db.example.com", "y", "verify-full"},
	} {
		a := Answers{"engine": "postgres", "host": c.host, "production": c.prod}
		if got := find(t, fs, "tls", a).Default; got != c.want {
			t.Errorf("tls for %s production=%q: %q, want %q", c.host, c.prod, got, c.want)
		}
	}
	// A detected mode and a draft beat the rule.
	fs = fieldsOf(t, "locksql", Defaults{Source: &shopDB})
	if got := find(t, fs, "tls", Answers{"engine": "postgres", "host": "db.example.com"}).Default; got != "disable" {
		t.Errorf("detected tls %q", got)
	}
	// Production forces verify-full even over a detected mode.
	if got := find(t, fs, "tls", Answers{"engine": "postgres", "host": "db.example.com", "production": "y"}).Default; got != "verify-full" {
		t.Errorf("production over detected tls %q", got)
	}
	fs = fieldsOf(t, "locksql", Defaults{Draft: Answers{"tls": "require"}})
	if got := find(t, fs, "tls", Answers{"engine": "postgres", "host": "db.example.com", "production": "y"}).Default; got != "require" {
		t.Errorf("draft tls over production %q", got)
	}
	if got := find(t, fs, "tls", Answers{"engine": "postgres", "host": "db.example.com"}).Default; got != "require" {
		t.Errorf("draft tls %q", got)
	}
	// Production is asked before TLS.
	var keys []string
	for _, f := range fieldsOf(t, "locksql", Defaults{}) {
		keys = append(keys, f.Key)
	}
	if slices.Index(keys, "production") > slices.Index(keys, "tls") {
		t.Errorf("order %v", keys)
	}
}

func TestAnswer(t *testing.T) {
	fs := fieldsOf(t, "locksql", Defaults{Source: &shopDB})
	pg := Answers{"engine": "postgres", "host": "host.docker.internal"}
	host, user, db := find(t, fs, "host", pg), find(t, fs, "user", pg), find(t, fs, "database", pg)
	port := find(t, fs, "port", pg)
	for _, c := range []struct {
		f           Field
		typed, want string
		reason      string
	}{
		{port, "", "55432", ""},
		{port, "6000", "6000", ""},
		{port, "x", "", "port: want a number"},
		{port, "-", "", "port: a value is needed"},
		{host, "-", "", "host: a value is needed"},
		{user, "", "shop", ""},
		{user, "-", "", ""},
		{user, "bob", "bob", ""},
		{db, "-", "", ""},
	} {
		v, r := Answer(c.f, c.typed, pg)
		if v != c.want || c.reason == "" && r != "" || c.reason != "" && !strings.Contains(r, c.reason) {
			t.Errorf("Answer(%s, %q) = %q, %q; want %q, %q", c.f.Key, c.typed, v, r, c.want, c.reason)
		}
	}
	// No default: empty keeps the empty answer.
	mq := fieldsOf(t, "lockmq", Defaults{})
	vhost := find(t, mq, "vhost", nil)
	if v, r := Answer(vhost, "", nil); v != "" || r != "" {
		t.Errorf("optional empty: %q %q", v, r)
	}
	if _, r := Answer(find(t, fieldsOf(t, "lockfile", Defaults{}), "bucket", Answers{"source": "s3"}), "", nil); r == "" {
		t.Error("a required empty answer was accepted")
	}
}

func TestVaultPathFollowsDraftName(t *testing.T) {
	fs := fieldsOf(t, "locksql", Defaults{Source: &shopDB, Draft: Answers{"name": "orders-db"}})
	if got := find(t, fs, "vault-path", Answers{"engine": "postgres", "credentials": "vault"}).Default; got != "database/creds/orders-db" {
		t.Errorf("vault path %q", got)
	}
}

func TestSQLitePathRefusesADirectory(t *testing.T) {
	f := find(t, fieldsOf(t, "locksql", Defaults{}), "path", Answers{"engine": "sqlite"})
	if r := f.Check(t.TempDir(), nil); r == "" {
		t.Error("a directory was accepted")
	}
	if r := f.Check(filepath.Join(t.TempDir(), "shop.db"), nil); r != "" {
		t.Errorf("new file refused: %q", r)
	}
}
