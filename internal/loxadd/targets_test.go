package loxadd

import (
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// The shop project's sources, as detection reports them.
var (
	shopDB    = loxinit.Source{Kind: loxinit.KindPostgres, Service: "db", Host: loxinit.DockerHost, Port: 55432, User: "shop", Database: "shop", TLS: "disable", Local: true}
	shopMQ    = loxinit.Source{Kind: loxinit.KindRabbitMQ, Service: "mq", Host: loxinit.DockerHost, Port: 55672, AMQPPort: 55673, User: "orders", VHost: "orders", Local: true}
	inventory = loxinit.Source{Kind: loxinit.KindMySQL, Host: "inventory.internal", Port: 3307, User: "stock", Database: "stock", TLS: "verify-full"}
)

func TestSQLTarget(t *testing.T) {
	for _, c := range []struct {
		s    loxinit.Source
		tls  string
		want string
	}{
		{shopDB, "disable", "--engine postgres --host host.docker.internal --port 55432 --user shop --database shop --tls disable"},
		{inventory, "verify-full", "--engine mysql --host inventory.internal --port 3307 --user stock --database stock --tls verify-full"},
		{loxinit.Source{Kind: loxinit.KindMariaDB, Host: "db.example.com", Port: 3306}, "", "--engine mariadb --host db.example.com --port 3306"},
	} {
		if got := strings.Join(SQLTarget(c.s, c.tls), " "); got != c.want {
			t.Errorf("SQLTarget = %q, want %q", got, c.want)
		}
	}
}

func TestMQTarget(t *testing.T) {
	want := "--url http://host.docker.internal:55672 --user orders --vhost orders --amqp-url amqp://host.docker.internal:55673"
	if got := strings.Join(MQTarget(shopMQ), " "); got != want {
		t.Errorf("MQTarget = %q, want %q", got, want)
	}
	bare := loxinit.Source{Kind: loxinit.KindRabbitMQ, Host: "mq.example.com", Port: 15672, MgmtTLS: true}
	if got := strings.Join(MQTarget(bare), " "); got != "--url https://mq.example.com:15672" {
		t.Errorf("MQTarget = %q", got)
	}
}

// disable on this machine, verify-full elsewhere and for production.
func TestDefaultTLS(t *testing.T) {
	for _, c := range []struct {
		s    loxinit.Source
		prod bool
		want string
	}{
		{shopDB, false, "disable"},
		{shopDB, true, "verify-full"},
		{inventory, false, "verify-full"},
	} {
		if got := DefaultTLS(c.s, c.prod); got != c.want {
			t.Errorf("DefaultTLS(%s, %v) = %q, want %q", c.s.Target(), c.prod, got, c.want)
		}
	}
}
