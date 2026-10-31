package family

import (
	"encoding/json"
	"path/filepath"
	"slices"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// UpFile is the name of what lox up tells lea, in the workspace's
// .lockfamily directory (which lea's agents only read): how to reach the
// locks it runs. Nothing in it is secret.
const UpFile = "up.json"

// UpState is lox up's contract with lea (version 1): lea mounts in its
// agents' containers each lock's socket volume, after checking that the
// volume carries compose's project label and the socket role (it never
// mounts any other volume of a lock), on /run/<type>; for a lockhttp
// instance, lea's gate mounts the socket volume and the gate's home,
// asks the hub at HubURL with HubKey pinned, and only lea's proxy joins
// HubNetwork.
type UpState struct {
	Version    int    `json:"version"`
	Project    string `json:"project"`
	Workspace  string `json:"workspace"`
	HubNetwork string `json:"hub_network"`
	HubURL     string `json:"hub_url"`
	HubKey     string `json:"hub_key"`
	// FacadeKeys are the host facades' keys the locks pin (lockkit
	// ticket.FacadeSet, public keys only): lea's lockhttp gate writes
	// them to a read-only file of its own and passes --facade-keys-file,
	// as lox up does for the consoles it runs. Absent before the first
	// apply.
	FacadeKeys *ticket.FacadeSet `json:"facade_keys,omitempty"`
	// LockHTTPGate 1: the locks below say what a lockhttp lock's gate
	// pins (Devices, RequireDevice, SealClear, Reveal, Profile) and
	// Devices is the paired devices. lea runs its gate in hub mode only
	// from 1 on (before, a lock's devices: true would not reach it).
	LockHTTPGate int `json:"lockhttp_gate"`
	// Devices are the paired devices the locks with UpLock.Devices pin
	// (lockkit ticket.DeviceSet, public keys only), as lox up mounts
	// them for its consoles. Absent while no device is paired.
	Devices *ticket.DeviceSet `json:"devices,omitempty"`
	Locks   map[string]UpLock `json:"locks"`
}

// UpLock is one lock of UpState.
type UpLock struct {
	Type    string `json:"type"`
	Profile string `json:"profile,omitempty"`
	// Socket is the console's socket volume (role socket).
	Socket string `json:"socket_volume"`
	// GateHome is the lockhttp gate's own volume (role gate-home).
	GateHome string `json:"gate_home_volume,omitempty"`
	// GID is the console's clients group, which lea's agents join.
	GID string `json:"client_gid"`
	// Reveal: the lock pins the host facades' keys (lockfamily.yaml
	// reveal: true). For a lockhttp instance, lea's gate then passes
	// --facade-keys-file with FacadeKeys; otherwise it does not (an
	// older gate refuses the flag).
	Reveal bool `json:"reveal,omitempty"`
	// Devices: the lock pins the paired devices (lockfamily.yaml
	// locks.<name>.devices: true). For a lockhttp instance, lea's gate
	// then pins UpState.Devices (--devices-file) and RequireDevice and
	// SealClear, which come from hub.mobile, as lox up passes them to the
	// consoles it runs (--require-device, --seal-clear). Without Devices,
	// neither is set.
	Devices       bool     `json:"devices,omitempty"`
	RequireDevice []string `json:"require_device,omitempty"`
	SealClear     bool     `json:"seal_clear,omitempty"`
}

// NewUpState is the contract for c, run as compose project project, with
// devices paired.
func NewUpState(c *Config, project, ws, hubKey string, devices []ticket.Device) UpState {
	s := UpState{Version: 1, Project: project, Workspace: ws, HubNetwork: project + "_lockhub",
		HubURL: "http://lockhub:8443", HubKey: hubKey, LockHTTPGate: 1, Locks: map[string]UpLock{}}
	if len(devices) > 0 {
		s.Devices = &ticket.DeviceSet{V: ticket.Version, Devices: devices}
	}
	for _, n := range c.Instances() {
		l := c.Locks[n]
		ul := UpLock{Type: l.Type, Profile: l.Profile, Socket: project + "_" + n + "-run", GID: Kinds[l.Type].GID, Reveal: l.Reveal}
		if l.Devices {
			ul.Devices = true
			if m := c.Hub.Mobile; m != nil {
				ul.RequireDevice, ul.SealClear = slices.Clone(m.RequireDevice), m.SealClear
			}
		}
		if Kinds[l.Type].Gate {
			ul.GateHome = project + "_" + n + "-gate"
		}
		s.Locks[n] = ul
	}
	return s
}

func writeUpState(ws string, s UpState) error {
	d := filepath.Join(ws, Dir)
	if err := ensureDir(filepath.Join(d, FileName)); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	// A fresh temporary file renamed over up.json: a planted link is
	// replaced, never followed; 0644, the user's.
	return writeFileMode(filepath.Join(d, UpFile), append(b, '\n'), 0o644)
}
