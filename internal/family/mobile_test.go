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

// mobileYAML is yamlConf with mobile, crm-prod pinning devices.
func mobileYAML() string {
	return strings.Replace(yamlConf(mobileConf), "    image: "+sqlImg+"\n", "    image: "+sqlImg+"\n    devices: true\n", 1)
}

func TestMobileConfig(t *testing.T) {
	for name, conf := range map[string]string{
		"mobile without origin":  "  facades: [tty, mobile]\n",
		"origin without mobile":  "  mobile:\n    origin: https://hub.example.net\n",
		"http origin":            "  facades: [mobile]\n  mobile:\n    origin: http://hub.example.net\n",
		"origin with path":       "  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net/x\n",
		"unknown risk":           "  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    require_device: [writes]\n",
		"low port":               "  facades: [mobile]\n  mobile:\n    origin: https://hub.example.net\n    port: 80\n",
		"require without a lock": mobileConf,
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
	os.WriteFile(p, []byte(mobileYAML()), 0o644)
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
	paths.Devices, paths.DevicesID = "/s/devices.json", "sha256:aa"
	out = Compose(c, paths)
	if strings.Count(out, `lockfamily.devices: "sha256:aa"`) != 1 {
		t.Error("the locks do not carry the devices' identity")
	}
	paths.DevicesID = "sha256:bb"
	if Compose(c, paths) == out {
		t.Error("a change of the paired devices does not change the locks")
	}
	for _, want := range []string{
		`"--devices-file", "/run/lockfamily/devices.json", "--seal-clear", "--require-device", "prod-write,policy-loosen"]`,
		"source: \"/s/devices.json\"\n        target: /run/lockfamily/devices.json\n        read_only: true",
	} {
		if strings.Count(out, want) != 1 {
			t.Errorf("compose has %q %d times, want once (crm-prod only)", want, strings.Count(out, want))
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

// require_device without a paired device would let the locks take the
// hub's approvals again: lock up refuses to apply it.
func TestRequireDeviceWithoutDeviceFailsClosed(t *testing.T) {
	w := newWS(t, mobileYAML())
	if _, err := w.up("y\n", newFake()); err == nil || !strings.Contains(err.Error(), "require_device") {
		t.Fatalf("lock up applied require_device with no device: %v", err)
	}
	a := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	if err := PinDevice(filepath.Join(w.dir, "state"), a.Device()); err != nil {
		t.Fatal(err)
	}
	out, err := w.up("y\n", newFake())
	if err != nil || !strings.Contains(out, "  device phone webauthn:") {
		t.Fatalf("with a device: %v\n%s", err, out)
	}
}
