package family

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/DavidGodefroid/lockkit/ticket"
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
	paths := Paths{Workspace: "/w", HubData: "/s/hub", FacadeDir: "/r/lockhub", User: "0:0"}
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
		`"--devices-file", "/run/lockfamily-devices/devices.json", "--seal-clear", "--require-device", "prod-write,policy-loosen"]`,
		"source: \"/s/devices.json\"\n        target: /run/lockfamily-devices/devices.json\n        read_only: true",
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
	sum := strings.Join(Summary(c, "", nil, nil), "\n")
	for _, want := range []string{"lock crm-prod accepts only device-signed approvals of prod-write,policy-loosen",
		"lock crm-prod seals its clear screens to them", "lock events pins no device: not answered on mobile"} {
		if !strings.Contains(sum, want) {
			t.Errorf("review lacks %q", want)
		}
	}
}

func TestMobilePushComposeAndReview(t *testing.T) {
	// Without push: no route out, no flag (nothing changes).
	w := newWS(t, mobileYAML())
	a := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	state := filepath.Join(w.dir, "state")
	if err := PinDevice(state, a.Device()); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	out, err := w.up("y\n", f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	cy, _ := os.ReadFile(filepath.Join(state, "compose.yaml"))
	if strings.Contains(string(cy), "egress-hub") || strings.Contains(string(cy), "--mobile-push") || strings.Contains(out, "push") {
		t.Fatalf("push without hub.mobile.push:\n%s\n%s", out, cy)
	}
	// With push: the flag, the hub's route out, and both in the review.
	os.WriteFile(w.file, []byte(strings.Replace(mobileYAML(), "    seal_clear: true\n", "    seal_clear: true\n    push: true\n", 1)), 0o644)
	out, err = w.up("y\n", &fake{keys: f.keys})
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if !strings.Contains(out, "+ hub mobile push on: the hub gets a route out (egress-hub)") || !strings.Contains(out, "*.push.apple.com") {
		t.Errorf("push not reviewed:\n%s", out)
	}
	cy, _ = os.ReadFile(filepath.Join(state, "compose.yaml"))
	for _, want := range []string{
		`"--mobile-origin", "https://hub.example.net", "--mobile-push"]`,
		`networks: [lockhub, "egress-hub", "mobile-hub"]`,
		"  \"egress-hub\": {}\n",
	} {
		if !strings.Contains(string(cy), want) {
			t.Errorf("compose lacks %q:\n%s", want, cy)
		}
	}
	// push is a mobile setting: without the mobile facade it is refused.
	p := filepath.Join(t.TempDir(), "lockfamily.yaml")
	os.WriteFile(p, []byte(yamlConf("  mobile:\n    origin: https://hub.example.net\n    push: true\n")), 0o644)
	if _, err := Load(p); err == nil {
		t.Error("push without the mobile facade: accepted")
	}
}

// up.json says what lea's lockhttp gate must pin, as lock up passes it to
// the consoles it runs (deviceArgs): the paired devices, and for a lock
// with devices: true, hub.mobile's require_device and seal_clear; the
// profile the console serves (lockhub#40).
func TestUpJSONSaysWhatTheGatePins(t *testing.T) {
	conf := mobileYAML() + "  web:\n    type: lockhttp\n    image: " + httpImg + "\n    devices: true\n    reveal: true\n    profile: strict\n"
	w := newWS(t, conf)
	a := devicetest.New("hub.example.net", "https://hub.example.net", "phone")
	state := filepath.Join(w.dir, "state")
	if err := PinDevice(state, a.Device()); err != nil {
		t.Fatal(err)
	}
	f := newFake()
	f.keys["web"] = pubKey()
	if out, err := w.up("y\n", f); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(filepath.Dir(w.file), UpFile))
	if err != nil {
		t.Fatal(err)
	}
	var s UpState
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	if s.LockHTTPGate != 1 {
		t.Errorf("lockhttp_gate %d", s.LockHTTPGate)
	}
	// The devices, exactly the set the consoles mount, in a form the gate
	// reads once canonical.
	want, _ := ReadDevices(state)
	if s.Devices == nil || s.Devices.V != ticket.Version || len(s.Devices.Devices) != 1 || s.Devices.Devices[0].ID != want[0].ID {
		t.Fatalf("devices %+v", s.Devices)
	}
	cb, err := ticket.MarshalDevices(s.Devices.Devices)
	snaps, _ := filepath.Glob(filepath.Join(state, "devices-*.json"))
	if err != nil || len(snaps) != 1 {
		t.Fatalf("%v %v", err, snaps)
	}
	if mounted, _ := os.ReadFile(snaps[0]); string(cb) != string(mounted) {
		t.Errorf("up.json devices differ from the consoles' snapshot:\n%s\n%s", cb, mounted)
	}
	if _, err := ticket.ParseDevices(cb); err != nil {
		t.Errorf("the gate would refuse the devices: %v", err)
	}
	web := s.Locks["web"]
	if !web.Devices || !web.SealClear || strings.Join(web.RequireDevice, ",") != "prod-write,policy-loosen" || !web.Reveal || web.Profile != "strict" {
		t.Errorf("web: %+v", web)
	}
	if crm := s.Locks["crm-prod"]; !crm.Devices || !crm.SealClear || len(crm.RequireDevice) != 2 {
		t.Errorf("crm-prod: %+v", crm)
	}
	// A lock without devices: true pins none, whatever hub.mobile says.
	if ev := s.Locks["events"]; ev.Devices || ev.SealClear || ev.RequireDevice != nil {
		t.Errorf("events: %+v", ev)
	}
}
