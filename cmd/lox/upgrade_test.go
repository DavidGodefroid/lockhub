package main

import "testing"

func TestUpgraderPinsThisLox(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "0.9.1"
	u := upgrader(nil)
	if u.Pins["lockhub"] != "v0.9.1" || u.Pins["locksql"] == "" || u.Image == nil {
		t.Errorf("pins %v", u.Pins)
	}
	version = "dev"
	if _, ok := upgrader(nil).Pins["lockhub"]; ok {
		t.Error("a dev build upgrades the hub")
	}
}
