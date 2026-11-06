package loxinit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// secret is planted in every file detection reads: it must never come
// out of it.
const secret = "Sup3r-s3cret-value-9f2c"

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// shopProject is a project with a compose file (postgres, rabbitmq, an
// app), a .env and a config/ file, each holding the secret.
func shopProject(t *testing.T) string {
	root := t.TempDir()
	write(t, root, "compose.yaml", `services:
  db:
    image: postgres:17
    ports: ["55432:5432"]
    environment:
      POSTGRES_USER: shop
      POSTGRES_DB: ${SHOP_DB:-shop}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
  mq:
    image: rabbitmq:4.1.8-management
    ports:
      - "55672:15672"
      - target: 5672
        published: "55673"
    environment:
      - RABBITMQ_DEFAULT_USER=orders
      - RABBITMQ_DEFAULT_PASS=`+secret+`
      - RABBITMQ_DEFAULT_VHOST=orders
  app:
    image: shop/app:1
    environment:
      DATABASE_URL: postgres://shop:`+secret+`@db:5432/shop
`)
	write(t, root, ".env", "# local settings\nPOSTGRES_PASSWORD="+secret+"\nexport API_TOKEN='"+secret+"'\nDATABASE_URL=postgres://shop:"+secret+"@localhost:55432/shop?sslmode=disable\n")
	write(t, root, "config/inventory.yaml", "inventory:\n  dsn: \"mysql://stock:"+secret+"@inventory.internal:3307/stock?ssl-mode=VERIFY_IDENTITY\"\n")
	return root
}

func TestDetectShopProject(t *testing.T) {
	root := shopProject(t)
	got, warns := Detect(root)
	if len(warns) != 0 {
		t.Errorf("warnings: %q", warns)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 sources, got %d: %+v", len(got), got)
	}
	db, mq, inv := got[0], got[1], got[2]
	if db.Kind != KindPostgres || db.Service != "db" || db.Host != DockerHost || db.Port != 55432 || db.User != "shop" || db.Database != "shop" || !db.Local || db.TLS != "disable" {
		t.Errorf("db: %+v", db)
	}
	if !strings.Contains(strings.Join(db.From, ","), ".env (DATABASE_URL)") {
		t.Errorf("db: .env's DATABASE_URL (localhost:55432) not merged into the compose service: %q", db.From)
	}
	if mq.Kind != KindRabbitMQ || mq.MgmtURL() != "http://host.docker.internal:55672" || mq.AMQPURL() != "amqp://host.docker.internal:55673" || mq.User != "orders" || mq.VHost != "orders" {
		t.Errorf("mq: %+v", mq)
	}
	if inv.Kind != KindMySQL || inv.Host != "inventory.internal" || inv.Port != 3307 || inv.User != "stock" || inv.Database != "stock" || inv.Local || inv.TLS != "verify-full" {
		t.Errorf("inventory: %+v", inv)
	}
	if strings.Contains(fmt.Sprintf("%#v %q", got, warns), secret) {
		t.Fatal("a secret came out of detection")
	}
}

func TestDetectRules(t *testing.T) {
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []string // Label Target User Database|VHost
		notes []string
	}{
		{"unpublished compose service", map[string]string{"compose.yml": "services:\n  pg:\n    image: docker.io/library/postgres:16\n"},
			[]string{"PostgreSQL pg:5432 postgres postgres"}, []string{"not published"}},
		{"laravel env, loopback rewritten", map[string]string{".env": "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_PORT=3306\nDB_DATABASE=orders\nDB_USERNAME=app\nDB_PASSWORD=" + secret + "\n"},
			[]string{"MySQL host.docker.internal:3306 app orders"}, nil},
		{"amqp url, management assumed", map[string]string{".env.local": "RABBITMQ_URL=amqp://app:" + secret + "@localhost/shop%2Fevents\n"},
			[]string{"RabbitMQ http://host.docker.internal:15672 app shop/events"}, []string{"15672 assumed"}},
		{"guest is noted", map[string]string{"docker-compose.yaml": "services:\n  rabbit:\n    image: bitnami/rabbitmq:4\n    ports: [\"15672:15672\", \"5672:5672\"]\n"},
			[]string{"RabbitMQ http://host.docker.internal:15672 guest "}, []string{"guest"}},
		{"keys without a host only feed compose", map[string]string{".env": "POSTGRES_USER=shop\n"}, nil, nil},
		{"mariadb from MYSQL_ keys", map[string]string{"compose.override.yaml": "services:\n  maria:\n    image: mariadb:11\n    ports: [\"3306:3306\"]\n    environment:\n      MYSQL_USER: stock\n      MYSQL_DATABASE: stock\n"},
			[]string{"MariaDB host.docker.internal:3306 stock stock"}, nil},
		{"unknown scheme and bad URL ignored", map[string]string{"config/app.toml": "url = \"redis://x\"\nother = \"postgres://%zz\"\n"}, nil, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			for f, b := range c.files {
				write(t, root, f, b)
			}
			got, _ := Detect(root)
			var lines, notes []string
			for _, s := range got {
				v := s.Database
				if s.Kind == KindRabbitMQ {
					v = s.VHost
				}
				lines = append(lines, strings.Join([]string{s.Label(), s.Target(), s.User, v}, " "))
				notes = append(notes, s.Notes...)
			}
			if strings.Join(lines, "|") != strings.Join(c.want, "|") {
				t.Errorf("got %q, want %q", lines, c.want)
			}
			for _, n := range c.notes {
				if !strings.Contains(strings.Join(notes, "|"), n) {
					t.Errorf("no note %q in %q", n, notes)
				}
			}
			if strings.Contains(fmt.Sprintf("%#v", got), secret) {
				t.Error("a secret came out of detection")
			}
		})
	}
}

// Detection reads only what it says: no link is followed, a big file is
// skipped with a warning naming it, and nothing is written.
func TestDetectReadsOnlyProjectFiles(t *testing.T) {
	root := t.TempDir()
	out := t.TempDir()
	write(t, out, "compose.yaml", "services:\n  db:\n    image: postgres\n    ports: [\"5432:5432\"]\n")
	if err := os.Symlink(filepath.Join(out, "compose.yaml"), filepath.Join(root, "compose.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(out, filepath.Join(root, "config")); err != nil {
		t.Fatal(err)
	}
	write(t, root, ".env", "DATABASE_URL=postgres://a@db.example:5432/x\n"+strings.Repeat("#", maxFile))
	got, warns := Detect(root)
	if len(got) != 0 {
		t.Errorf("sources through links or a big file: %+v", got)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], ".env: over 256 KiB") {
		t.Errorf("warnings: %q", warns)
	}
	ents, _ := os.ReadDir(root)
	if len(ents) != 3 {
		t.Errorf("detection wrote in the project: %d entries", len(ents))
	}
}

func TestSecretKey(t *testing.T) {
	for k, want := range map[string]bool{"DB_PASSWORD": true, "RABBITMQ_DEFAULT_PASS": true, "api-token": true, "PGPASSWORD": true, "KEYCLOAK_URL": false,
		"AWS_SECRET_ACCESS_KEY": true, "DATABASE_URL": false, "DB_USER": false, "MYSQL_ROOT_PASSWORD": true, "SESSION_COOKIE": true} {
		if SecretKey(k) != want {
			t.Errorf("SecretKey(%q) = %v", k, !want)
		}
	}
}

// The log stores a project names (compose images, .env URLs) and this
// host's logs are locklog's sources: never a user or a password kept.
func TestDetectLogSources(t *testing.T) {
	root := t.TempDir()
	write(t, root, "compose.yaml", `services:
  loki:
    image: grafana/loki:3.5.0
    ports: ["3100:3100"]
  search:
    image: docker.elastic.co/elasticsearch/elasticsearch:9.1.0
  dash:
    image: opensearchproject/opensearch-dashboards:3
`)
	write(t, root, ".env", "OPENSEARCH_URL=https://admin:"+secret+"@search.example.com:9200,https://b.example.com\nLOKI_ADDR=http://localhost:3100\n")
	got, _ := Detect(root)
	var lines []string
	for _, s := range got {
		lines = append(lines, fmt.Sprintf("%s %s %s %v", s.Lock(), s.Kind, s.Target(), s.From))
		if strings.Contains(fmt.Sprintf("%+v", s), secret) || s.User != "" {
			t.Errorf("a secret or a user kept: %+v", s)
		}
		if !strings.Contains(strings.Join(s.Notes, " "), ".locklog/config.toml by hand") {
			t.Errorf("%s: no note on the remote source: %v", s.Kind, s.Notes)
		}
	}
	want := []string{
		"locklog loki http://host.docker.internal:3100 [compose.yaml (service loki) .env (LOKI_ADDR)]",
		"locklog elasticsearch http://search:9200 [compose.yaml (service search)]",
		"locklog opensearch https://search.example.com:9200 [.env (OPENSEARCH_URL)]",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Errorf("sources:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	isDir := func(d string) bool { return d == "/var/log" || d == "/run/log/journal" }
	if d := HostLogDirs("linux", isDir); strings.Join(d, " ") != "/run/log/journal /var/log" {
		t.Errorf("linux: %v", d)
	}
	if d := HostLogDirs("darwin", isDir); d != nil {
		t.Errorf("darwin: %v", d)
	}
	if HostLogs(nil) != nil {
		t.Error("no directory, a source")
	}
	if s := HostLogs([]string{"/var/log"}); s.Lock() != "locklog" || s.Target() != "this host" || !s.Local {
		t.Errorf("host logs: %+v", s)
	}
}
