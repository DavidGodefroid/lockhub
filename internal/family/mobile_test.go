package family

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket/devicetest"
)

const mobileConf = `  facades: [tty, deck, mobile]
  mobile:
    origin: https://hub.example.net
    seal_clear: true
    require_device: [prod-write, policy-loosen]
`

func TestMobileConfig(t *testing.T) {
	for name, conf := range map[string]string{
		"mobile without origin": "  facades: [tty, mobile]\n",
		"origin without mobile": "  mobile:\n    origin: https://hub.example.net\n",
		"http origin":           "  facades: [mobile]\n  mobile:\n    origin: http://hub.example.net\n",
		"origin with path":      "  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net/x\n",
		"unknown risk":          "  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    require_device: [writes]\n",
		"low port":              "  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    port: 80\n",
	} {
		p := filepath.Join(t.TempDir(), "lockfamily.yaml")
		os.WriteFile(p, []byte(yamlConf(conf)), 0o644)
		if _, err := Load(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestComposeMobile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	os.WriteFile(p, []byte(yamlConf(mobileConf)), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	paths := Paths{HubData: "/s/hub", FacadeDir: "/r/lockhub", HubPub: "/s/hub.pub", User: "0:0"}
	out := Compose(c, paths)
	for _, want := range []string{
		`"--mobile-listen", ":8444", "--mobile-origin", "https://hub.example.net"`,
		`ports: ["127.0.0.1:8444:8444"]`, // loopback only
		`networks: [lockhub, "mobile-hub"]`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("compose lacks %q", want)
		}
	}
	if strings.Contains(out, "devices-file") || strings.Contains(out, "seal-clear") {
		t.Error("device flags without a paired device")
	}
	paths.Devices = "/s/devices.json"
	out = Compose(c, paths)
	for _, want := range []string{
		`"--devices-file", "/run/lockfamily/devices.json", "--seal-clear", "--require-device", "prod-write,policy-loosen"]`,
		"source: \"/s/devices.json\"\n        target: /run/lockfamily/devices.json\n        read_only: true",
	} {
		if strings.Count(out, want) != 2 {
			t.Errorf("compose lacks %q for each lock", want)
		}
	}
	if strings.Contains(out, "0.0.0.0") || strings.Contains(out, `"8444:8444"`) {
		t.Error("mobile port published beyond loopback")
	}
}

func TestPinnedDevicesAreReviewed(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	a := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	if err := PinDevice(state, a.Device()); err != nil {
		t.Fatal(err)
	}
	devs, err := ReadDevices(state)
	if err != nil || len(devs) != 1 {
		t.Fatalf("%v %v", devs, err)
	}
	lines := devicesSummary(devs)
	if len(lines) != 1 || !strings.Contains(lines[0], devs[0].ID) || !strings.Contains(lines[0], "fingerprint") {
		t.Fatalf("summary %v", lines)
	}
	if ok, err := UnpinDevice(state, devs[0].ID); !ok || err != nil {
		t.Fatal(ok, err)
	}
	if devs, _ := ReadDevices(state); len(devs) != 0 {
		t.Fatal("still pinned")
	}
}
