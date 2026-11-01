package loxadd

import (
	"github.com/DavidGodefroid/lockhub/internal/loxinit"
)

// The shop project's sources, as detection reports them.
var (
	shopDB    = loxinit.Source{Kind: loxinit.KindPostgres, Service: "db", Host: loxinit.DockerHost, Port: 55432, User: "shop", Database: "shop", TLS: "disable", Local: true}
	shopMQ    = loxinit.Source{Kind: loxinit.KindRabbitMQ, Service: "mq", Host: loxinit.DockerHost, Port: 55672, AMQPPort: 55673, User: "orders", VHost: "orders", Local: true}
	inventory = loxinit.Source{Kind: loxinit.KindMySQL, Host: "inventory.internal", Port: 3307, User: "stock", Database: "stock", TLS: "verify-full"}
)
