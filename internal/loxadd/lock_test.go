package loxadd

import (
	"slices"
	"strings"
	"testing"
)

func TestProfileArgs(t *testing.T) {
	head := []string{"profile", "add", "--non-interactive", "--json", "--project", "/p"}
	cases := []struct {
		name  string
		lock  string
		a     Answers
		want  []string
		vault string
	}{
		{"locksql vault", "locksql", Answers{"name": "orders", "credentials": "vault", "vault-path": "database/creds/orders",
			"engine": "postgres", "host": "host.docker.internal", "port": "55432", "database": "orders", "tls": "disable", "user": "", "production": "n"},
			[]string{"--profile", "orders", "--credentials", "vault", "--vault-path", "database/creds/orders",
				"--engine", "postgres", "--host", "host.docker.internal", "--port", "55432", "--database", "orders", "--tls", "disable"}, ""},
		{"locksql ask with user, production", "locksql", Answers{"name": "shop", "credentials": "ask", "engine": "mysql", "host": "db.example.com",
			"port": "3306", "user": "app", "tls": "verify-full", "production": "y"},
			[]string{"--profile", "shop", "--credentials", "ask", "--production", "--engine", "mysql", "--host", "db.example.com",
				"--port", "3306", "--user", "app", "--tls", "verify-full"}, ""},
		{"locksql sqlite", "locksql", Answers{"name": "inv", "credentials": "ask", "engine": "sqlite", "path": "data/inv.db", "production": "no"},
			[]string{"--profile", "inv", "--credentials", "ask", "--engine", "sqlite", "--path", "data/inv.db"}, ""},
		{"lockmq", "lockmq", Answers{"name": "events", "credentials": "vault", "vault-path": "rabbitmq/creds/events", "url": "http://mq.example.com:15672",
			"user": "", "vhost": "shop", "amqp-url": "amqp://mq.example.com:5672", "vault-address": "https://vault.example.com:8200", "vault-namespace": "team", "vault-ca": "/etc/ca.pem"},
			[]string{"--profile", "events", "--credentials", "vault", "--vault-path", "rabbitmq/creds/events",
				"--url", "http://mq.example.com:15672", "--vhost", "shop", "--amqp-url", "amqp://mq.example.com:5672"}, "https://vault.example.com:8200"},
		{"lockfile s3", "lockfile", Answers{"name": "exports", "credentials": "ask", "source": "s3", "bucket": "shop-exports", "endpoint": "", "region": "eu-west-1"},
			[]string{"--profile", "exports", "--credentials", "ask", "--source", "s3", "--bucket", "shop-exports", "--region", "eu-west-1"}, ""},
		{"lockfile sftp", "lockfile", Answers{"name": "drop", "credentials": "ask", "source": "sftp", "host": "sftp.example.com", "port": "22", "user": "orders",
			"key": "/home/u/.ssh/id", "known-hosts": "", "base-dir": "in"},
			[]string{"--profile", "drop", "--credentials", "ask", "--source", "sftp", "--host", "sftp.example.com", "--port", "22", "--user", "orders",
				"--key", "/home/u/.ssh/id", "--base-dir", "in"}, ""},
		{"lockfile local, no credentials", "lockfile", Answers{"name": "local", "source": "local", "path": "/srv/files"},
			[]string{"--profile", "local", "--source", "local", "--path", "/srv/files"}, ""},
		{"lockhttp", "lockhttp", Answers{"name": "web", "production": "y"},
			[]string{"--profile", "web", "--production"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			l, err := Build(c.lock, c.a)
			if err != nil {
				t.Fatal(err)
			}
			got := l.ProfileArgs("/p")
			want := append(slices.Clone(head), c.want...)
			if !slices.Equal(got, want) {
				t.Fatalf("argv\n got %q\nwant %q", got, want)
			}
			for _, x := range got {
				if x == "" {
					t.Fatalf("empty argument in %q", got)
				}
			}
			if (l.Vault != nil) != (c.vault != "") || (l.Vault != nil && l.Vault.Address != c.vault) {
				t.Fatalf("vault = %+v, want address %q", l.Vault, c.vault)
			}
			if l.Type != c.lock || l.Profile != c.a["name"] {
				t.Fatalf("lock = %+v", l)
			}
			joined := strings.Join(got, " ")
			for _, bad := range []string{"password", "token", "secret"} {
				if strings.Contains(joined, "--"+bad) {
					t.Fatalf("a secret flag in %q", got)
				}
			}
		})
	}
}

func TestBuildRefusals(t *testing.T) {
	if _, err := Build("lockzip", Answers{}); err == nil {
		t.Fatal("unknown lock accepted")
	}
	if _, err := Build("locksql", Answers{"credentials": "vault"}); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("missing name: %v", err)
	}
	if _, err := Build("locksql", Answers{"name": "x", "credentials": "vault"}); err == nil || !strings.Contains(err.Error(), "vault-path") {
		t.Fatalf("vault without path: %v", err)
	}
}
