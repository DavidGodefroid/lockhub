package loxadd

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// Answers are the values typed (or given as flags) so far, by field key.
// A key is the flag name of the lock's own `add` command; it never holds a
// secret (a key file is a path, never its content).
type Answers map[string]string

// Field is one question of `lox add`.
type Field struct {
	Key, Label string
	Choices    []string
	Default    string
	// DefaultFrom, when not nil, computes the default from the answers
	// (and the flags given): a non-empty result replaces Default. An empty
	// answer that took it is computed again once every field is answered,
	// so it follows a later answer (the Vault path follows the name).
	DefaultFrom func(a Answers) string
	// Empty is "" for a required value, else the meaning of an empty answer.
	Empty string
	YesNo bool
	// Check says why v is refused ("" when it is fine); a is what was
	// answered so far. The reason names the key, never the value. An empty
	// answer takes Default before Check; Check("") means the empty answer
	// was kept: refused when required, the Empty meaning when optional.
	// Answer does all of this.
	Check func(v string, a Answers) string
	// When says whether the field is asked, given the answers so far
	// (nil: always).
	When func(a Answers) bool
}

// Defaults are what the questions propose.
type Defaults struct {
	// Source is a detected data source, if the lock is made from one.
	Source *loxinit.Source
	// Declared are the names of the locks declared already.
	Declared []string
	// VaultSet: lockfamily.yaml has its vault block already.
	VaultSet bool
	// Draft are answers kept from an earlier try: they become the defaults.
	Draft Answers
}

// Prompt is the question as the terminal shows it.
func Prompt(f Field) string {
	if f.YesNo {
		if strings.HasPrefix(strings.ToLower(f.Default), "y") {
			return f.Label + " [Y/n] "
		}
		return f.Label + " [y/N] "
	}
	p := f.Label
	if f.Empty == "" {
		p += " (required)"
	} else if f.Default != "" {
		p += " (optional: - = " + f.Empty + ")"
	} else {
		p += " (optional: empty = " + f.Empty + ")"
	}
	if f.Default != "" {
		p += " [" + f.Default + "]"
	}
	return p + ": "
}

// Fields are the questions of `lox add` for lock, in the order they are
// asked.
func Fields(lock string, d Defaults) ([]Field, error) {
	var fs []Field
	switch lock {
	case "locksql":
		fs = sqlFields(d)
	case "lockmq":
		fs = mqFields(d)
	case "lockfile":
		fs = fileFields(d)
	case "lockhttp":
		fs = []Field{nameField(d, "web")}
	default:
		return nil, fmt.Errorf("lock: want locksql, lockmq, lockfile or lockhttp")
	}
	for i := range fs {
		f := &fs[i]
		if v := d.Draft[f.Key]; v != "" {
			f.Default, f.DefaultFrom = v, nil
		}
		check := f.Check
		required := f.Empty == ""
		key := f.Key
		f.Check = func(v string, a Answers) string {
			if v == "" {
				if required {
					return key + ": a value is needed"
				}
				return ""
			}
			if check == nil {
				return ""
			}
			return check(v, a)
		}
	}
	return fs, nil
}

// Answer is the value of field f for what was typed: an empty answer takes
// Default, "-" chooses the optional meaning (the value ""), then Check
// runs. reason is "" when the value is accepted.
func Answer(f Field, typed string, a Answers) (value, reason string) {
	if typed == "-" {
		if f.Empty == "" {
			return "", f.Key + ": a value is needed"
		}
		return "", ""
	}
	if typed == "" {
		typed = f.Default
	}
	if f.Check != nil {
		if r := f.Check(typed, a); r != "" {
			return "", r
		}
	}
	return typed, ""
}

// hostIsLocal: host names this machine (loopback, localhost, or the name a
// console gives the host).
func hostIsLocal(host string) bool {
	h := strings.ToLower(strings.Trim(host, "[]"))
	if h == "localhost" || h == loxinit.DockerHost {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func eq(key, val string) func(Answers) bool { return func(a Answers) bool { return a[key] == val } }

func and(fs ...func(Answers) bool) func(Answers) bool {
	return func(a Answers) bool {
		for _, f := range fs {
			if f != nil && !f(a) {
				return false
			}
		}
		return true
	}
}

func not(f func(Answers) bool) func(Answers) bool { return func(a Answers) bool { return !f(a) } }

func oneOf(key, reason string, choices ...string) func(string, Answers) string {
	return func(v string, _ Answers) string {
		if slices.Contains(choices, v) {
			return ""
		}
		return key + ": " + reason
	}
}

// safe is the first check of every text value: no control character, no
// embedded password.
func safe(key, v string) string {
	switch unsafeValue(v) {
	case "":
		return ""
	case "it embeds a password":
		return key + ": it embeds a password: type the target without it (the console asks for the password at its start)"
	}
	return key + ": it holds a control character"
}

// text checks a plain-text value. A colon is how a password gets typed
// after a name (name:secret, name:secret@host), and no plain-text key has a
// use for one.
func text(key string) func(string, Answers) string {
	return func(v string, _ Answers) string {
		if r := safe(key, v); r != "" {
			return r
		}
		if strings.Contains(v, ":") {
			return key + ": it embeds a password: type the target without it (the console asks for the password at its start)"
		}
		return ""
	}
}

func checkHost(v string, _ Answers) string {
	const bad = "host: a host name or address, without a port or scheme"
	if r := safe("host", v); r != "" {
		return r
	}
	if strings.ContainsAny(v, "/@ \t?#") {
		return bad
	}
	if net.ParseIP(strings.Trim(v, "[]")) != nil {
		return ""
	}
	if strings.ContainsAny(v, ":[]") {
		return bad
	}
	return ""
}

func checkPort(v string, _ Answers) string {
	if n, err := strconv.Atoi(v); err != nil || n < 1 || n > 65535 {
		return "port: want a number from 1 to 65535"
	}
	return ""
}

// checkURL accepts an absolute URL of one of schemes, with a host and no
// password.
func checkURL(key, reason string, schemes ...string) func(string, Answers) string {
	return func(v string, _ Answers) string {
		if r := safe(key, v); r != "" {
			return r
		}
		u, err := url.Parse(v)
		if err != nil || u.Host == "" || !slices.Contains(schemes, u.Scheme) {
			return key + ": " + reason
		}
		return ""
	}
}

var bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

func checkBucket(v string, _ Answers) string {
	if !bucketName.MatchString(v) {
		return "bucket: a bucket name, not a URL (such as shop-invoices)"
	}
	return ""
}

// checkDBFile accepts an absolute path that is not a directory.
func checkDBFile(key string) func(string, Answers) string {
	return func(v string, _ Answers) string {
		if r := safe(key, v); r != "" {
			return r
		}
		if !filepath.IsAbs(v) {
			return key + ": want an absolute path to a file"
		}
		if fi, err := os.Stat(v); err == nil && fi.IsDir() {
			return key + ": that is a directory: want a file"
		}
		return ""
	}
}

func checkAbsDir(key string) func(string, Answers) string {
	return func(v string, _ Answers) string {
		if r := safe(key, v); r != "" {
			return r
		}
		if !filepath.IsAbs(v) {
			return key + ": want an absolute path"
		}
		return ""
	}
}

// checkFile accepts an absolute path to a regular file; own also wants the
// file to be the user's. It never reads the file.
func checkFile(key string, own bool) func(string, Answers) string {
	return func(v string, _ Answers) string {
		if r := safe(key, v); r != "" {
			return r
		}
		if !filepath.IsAbs(v) {
			return key + ": want an absolute path to a file"
		}
		fi, err := os.Stat(v)
		if err != nil || !fi.Mode().IsRegular() {
			return key + ": want an absolute path to a regular file"
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); own && ok && int(st.Uid) != os.Getuid() {
			return key + ": the file is not yours"
		}
		return ""
	}
}

// checkVault runs the family's own rule for a vault: field, so lox add,
// lox vault set and the file's load refuse the same values with the same
// text.
func checkVault(key string, rule func(string) error) func(string, Answers) string {
	return func(v string, _ Answers) string {
		if r := safe(key, v); r != "" {
			return r
		}
		if err := rule(v); err != nil {
			return err.Error()
		}
		return ""
	}
}

func checkYesNo(v string, _ Answers) string {
	switch strings.ToLower(v) {
	case "y", "yes", "n", "no":
		return ""
	}
	return "production: want y or n"
}

func checkVaultPath(v string, _ Answers) string {
	if r := safe("vault-path", v); r != "" {
		return r
	}
	if strings.ContainsAny(v, " \t") || strings.Contains(v, "..") || strings.HasPrefix(v, "/") {
		return "vault-path: a path such as secret/data/shop, without spaces or .."
	}
	return ""
}

func nameField(d Defaults, def string) Field {
	return Field{Key: "name", Label: "Name", Default: uniqueName(def, func(n string) bool { return slices.Contains(d.Declared, n) }),
		Check: func(v string, _ Answers) string {
			if n := cleanName(v); n != v || n == "" {
				return "name: lower case letters, digits and -, at most 40 characters"
			}
			if slices.Contains(d.Declared, v) {
				return "name: a lock named " + v + " is declared already"
			}
			return ""
		}}
}

func productionField(when func(Answers) bool) Field {
	return Field{Key: "production", Label: "Production? (each approval needs the profile name typed)", YesNo: true, Default: "n", Check: checkYesNo, When: when}
}

func credentialsField(when func(Answers) bool) Field {
	return Field{Key: "credentials", Label: "Credentials: ask (typed, masked, at the console's start) or vault", Choices: []string{CredAsk, CredVault}, Default: CredAsk,
		Check: oneOf("credentials", "want ask or vault", CredAsk, CredVault), When: when}
}

// vaultFields are the vault path of one lock, then the vault block when
// the file has none yet. The path's default is prefix and the lock's name:
// the suggested one until the name is answered (it is asked last).
func vaultFields(d Defaults, prefix, suggested string, when func(Answers) bool) []Field {
	w := and(when, eq("credentials", CredVault))
	fs := []Field{{Key: "vault-path", Label: "Vault path", Default: prefix + vaultName(d, suggested), Check: checkVaultPath, When: w,
		DefaultFrom: func(a Answers) string {
			if n := a["name"]; n != "" {
				return prefix + n
			}
			return ""
		}}}
	if d.VaultSet {
		return fs
	}
	return append(fs,
		Field{Key: "vault-address", Label: "Vault address, such as https://vault.example.com:8200", Check: checkVault("vault-address", family.ValidateVaultAddress), When: w},
		Field{Key: "vault-namespace", Label: "Vault namespace", Empty: "the root namespace", Check: checkVault("vault-namespace", family.ValidateVaultNamespace), When: w},
		Field{Key: "vault-ca", Label: "Vault CA file", Empty: "the system's CA certificates", Check: checkVault("vault-ca", family.ValidateVaultCAFile), When: w},
	)
}

// tlsField is one of the three TLS questions, exactly one of which is asked:
// production (default verify-full, even over a detected mode), a database on
// this machine (default disable) or another (default verify-full). A detected
// mode beats the host rule but not production; a draft beats all.
func tlsField(detected string, variant string) Field {
	def := "verify-full"
	switch variant {
	case "local":
		def = "disable"
		fallthrough
	case "remote":
		if detected != "" {
			def = detected
		}
	}
	return Field{Key: "tls", Label: "TLS: disable, prefer, require, verify-ca or verify-full", Choices: TLSModes, Default: def,
		Check: oneOf("tls", "want disable, prefer, require, verify-ca or verify-full", TLSModes...),
		When: func(a Answers) bool {
			if a["engine"] == "sqlite" {
				return false
			}
			prod := strings.HasPrefix(strings.ToLower(a["production"]), "y")
			switch variant {
			case "prod":
				return prod
			case "local":
				return !prod && hostIsLocal(a["host"])
			}
			return !prod && !hostIsLocal(a["host"])
		}}
}

func vaultName(d Defaults, suggested string) string {
	if n := d.Draft["name"]; n != "" {
		return n
	}
	return suggested
}

func sqlFields(d Defaults) []Field {
	engines := []string{loxinit.KindPostgres, loxinit.KindMySQL, loxinit.KindMariaDB, "sqlite"}
	engine, host, user, database := loxinit.KindPostgres, loxinit.DockerHost, "", ""
	var tls string // a detected TLS mode, which beats the host rule
	var s loxinit.Source
	if d.Source != nil {
		s = *d.Source
		if slices.Contains(engines[:3], s.Kind) {
			engine = s.Kind
		}
		if s.Host != "" {
			host = s.Host
		}
		user, database = s.User, s.Database
		tls = s.TLS
	}
	suggested := uniqueName(SuggestName(s), func(n string) bool { return slices.Contains(d.Declared, n) })
	remote := not(eq("engine", "sqlite"))
	port := func(def string, engines ...string) Field {
		p := def
		if d.Source != nil && s.Port > 0 && slices.Contains(engines, s.Kind) {
			p = strconv.Itoa(s.Port)
		}
		return Field{Key: "port", Label: "Port", Default: p, Check: checkPort,
			When: func(a Answers) bool { return slices.Contains(engines, a["engine"]) }}
	}
	fs := []Field{
		{Key: "engine", Label: "Engine: postgres, mysql, mariadb or sqlite", Choices: engines, Default: engine, Check: oneOf("engine", "want postgres, mysql, mariadb or sqlite", engines...)},
		{Key: "path", Label: "Path", Check: checkDBFile("path"), When: eq("engine", "sqlite")},
		{Key: "host", Label: "Host", Default: host, Check: checkHost, When: remote},
		port("5432", loxinit.KindPostgres),
		port("3306", loxinit.KindMySQL, loxinit.KindMariaDB),
		{Key: "user", Label: "User", Empty: "the console asks for it at start with the password", Default: user, Check: text("user"), When: remote},
		{Key: "database", Label: "Database", Empty: "the server's default database", Default: database, Check: text("database"), When: remote},
		productionField(nil),
		tlsField(tls, "prod"),
		tlsField(tls, "local"),
		tlsField(tls, "remote"),
		credentialsField(remote),
	}
	fs = append(fs, vaultFields(d, "database/creds/", suggested, remote)...)
	return append(fs, nameField(d, SuggestName(s)))
}

func mqFields(d Defaults) []Field {
	url, user, vhost, amqp := "http://"+loxinit.DockerHost+":15672", "", "", ""
	var s loxinit.Source
	if d.Source != nil {
		s = *d.Source
		url, user, vhost, amqp = s.MgmtURL(), s.User, s.VHost, s.AMQPURL()
	} else {
		s.Kind = loxinit.KindRabbitMQ
	}
	name := SuggestName(s)
	fs := []Field{
		{Key: "url", Label: "Management URL", Default: url, Check: checkURL("url", "an http or https URL, such as http://mq.example.com:15672", "http", "https")},
		{Key: "user", Label: "User", Empty: "the console asks for it at start with the password", Default: user, Check: text("user")},
		{Key: "vhost", Label: "Vhost", Empty: "all vhosts the user can see", Default: vhost, Check: text("vhost")},
		{Key: "amqp-url", Label: "AMQP URL, such as amqp://<mgmt host>:5672", Empty: "no stream reads", Default: amqp, Check: checkURL("amqp-url", "an amqp or amqps URL, such as amqp://mq.example.com:5672", "amqp", "amqps")},
		productionField(nil),
		credentialsField(nil),
	}
	if amqp == "" {
		fs[3].DefaultFrom = amqpFromMgmt
	}
	fs = append(fs, vaultFields(d, "rabbitmq/creds/", uniqueName(name, func(n string) bool { return slices.Contains(d.Declared, n) }), nil)...)
	return append(fs, nameField(d, name))
}

// amqpFromMgmt is the AMQP URL on the management URL's host: amqp on
// 5672, or amqps on 5671 for an https management URL ("" when the URL has
// no host).
func amqpFromMgmt(a Answers) string {
	u, err := url.Parse(a["url"])
	if err != nil || u.Hostname() == "" {
		return ""
	}
	if u.Scheme == "https" {
		return "amqps://" + net.JoinHostPort(u.Hostname(), "5671")
	}
	return "amqp://" + net.JoinHostPort(u.Hostname(), "5672")
}

func fileFields(d Defaults) []Field {
	src := func(vals ...string) func(Answers) bool {
		return func(a Answers) bool { return slices.Contains(vals, a["source"]) }
	}
	s3 := src("s3")
	name := nameField(d, "files")
	fs := []Field{
		{Key: "source", Label: "Source: local, s3 or sftp", Choices: []string{"local", "s3", "sftp"}, Default: "s3", Check: oneOf("source", "want local, s3 or sftp", "local", "s3", "sftp")},
		{Key: "bucket", Label: "Bucket, a bucket name, not a URL", Check: checkBucket, When: s3},
		{Key: "endpoint", Label: "Endpoint, a URL with its scheme", Empty: "AWS",
			Check: checkURL("endpoint", "a URL with its scheme, such as https://minio.example.com:9000", "http", "https"), When: s3},
		{Key: "region", Label: "Region", Check: text("region"), When: and(s3, func(a Answers) bool { return a["endpoint"] == "" })},
		{Key: "region", Label: "Region", Empty: "the endpoint's default", Check: text("region"), When: and(s3, func(a Answers) bool { return a["endpoint"] != "" })},
		{Key: "path", Label: "Directory", Check: checkAbsDir("path"), When: src("local")},
		{Key: "host", Label: "Host", Check: checkHost, When: src("sftp")},
		{Key: "port", Label: "Port", Default: "22", Check: checkPort, When: src("sftp")},
		{Key: "user", Label: "User", Check: text("user"), When: src("sftp")},
		{Key: "auth", Label: "Auth: key or password", Choices: []string{"key", "password"}, Default: "key", Check: oneOf("auth", "want key or password", "key", "password"), When: src("sftp")},
		{Key: "key", Label: "Private key file, an absolute path", Check: checkFile("key", true), When: and(src("sftp"), eq("auth", "key"))},
		{Key: "known-hosts", Label: "Known hosts file", Check: checkFile("known-hosts", false), When: src("sftp")},
		{Key: "base-dir", Label: "Base directory", Empty: "the login directory", Check: text("base-dir"), When: src("sftp")},
		productionField(nil),
		credentialsField(src("s3", "sftp")),
	}
	fs = append(fs, vaultFields(d, "secret/data/lockfile/", name.Default, src("s3", "sftp"))...)
	return append(fs, name)
}
