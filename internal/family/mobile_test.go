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
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil || !strings.Contains(out, "  device phone webauthn:") {
		t.Fatalf("with a device: %v\n%s", err, out)
	}
	if len(f.missing) > 0 {
		t.Fatalf("compose mounted snapshots that did not exist yet: %v", f.missing)
	}
	state := filepath.Join(w.dir, "state")
	if o, err := AppliedMobileOrigin(state); err != nil || o != "https://hub.example.net" {
		t.Fatalf("applied origin %q %v", o, err)
	}
	// The locks mount the reviewed snapshot, not the live file.
	snaps, _ := filepath.Glob(filepath.Join(state, "devices-*.json"))
	if len(snaps) != 1 {
		t.Fatalf("snapshots %v", snaps)
	}
	b, _ := os.ReadFile(filepath.Join(state, "compose.yaml"))
	if !strings.Contains(string(b), "source: \""+snaps[0]+"\"") || strings.Contains(string(b), DevicesFile(state)+"\"") {
		t.Fatalf("compose does not mount the snapshot:\n%s", b)
	}
	// A second phone: a new snapshot, the old one removed after the up.
	b2 := devicetest.New("hub.example.net", "https://hub.example.net", "tablet")
	if err := PinDevice(state, b2.Device()); err != nil {
		t.Fatal(err)
	}
	f = newFake()
	if _, err := w.up("y\n", f); err != nil || len(f.missing) > 0 {
		t.Fatalf("after a device change: %v, missing %v", err, f.missing)
	}
	if now, _ := filepath.Glob(filepath.Join(state, "devices-*.json")); len(now) != 1 || now[0] == snaps[0] {
		t.Fatalf("snapshots after the change: %v (was %v)", now, snaps)
	}
}

// A lock that pins no device would refuse every phone decision: the hub
// does not route it to mobile; the review names what each lock does.
func TestMobileRoutingAndReview(t *testing.T) {
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	os.WriteFile(p, []byte(mobileYAML()), 0o644)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	r := Routes(c)
	if err := r.Allowed("crm-prod", "mobile", "write"); err != nil {
		t.Fatalf("the opted-in lock is not on mobile: %v", err)
	}
	if err := r.Allowed("events", "mobile", "read"); err == nil {
		t.Fatal("a lock that pins no device is answered on mobile")
	}
	if err := r.Allowed("events", "tty", "read"); err != nil {
		t.Fatalf("events lost the terminal: %v", err)
	}
	sum := strings.Join(Summary(c, "", nil), "\n")
	for _, want := range []string{"lock crm-prod accepts only device-signed approvals of prod-write,policy-loosen",
		"lock crm-prod seals its clear screens to them", "lock events pins no device: not answered on mobile"} {
		if !strings.Contains(sum, want) {
			t.Errorf("review lacks %q", want)
		}
	}
}
