package family

import (
	"encoding/json"
	"path/filepath"
)

// UpFile is the name of what lock up tells lea, in the workspace's
// .lockfamily directory (which lea's agents only read): how to reach the
// locks it runs. Nothing in it is secret.
const UpFile = "up.json"

// UpState is lock up's contract with lea (version 1): lea mounts in its
// agents' containers each lock's socket volume, after checking that the
// volume carries compose's project label and the socket role (it never
// mounts any other volume of a lock), on /run/<type>; for a lockhttp
// instance, lea's gate mounts the socket volume and the gate's home,
// asks the hub at HubURL with HubKey pinned, and only lea's proxy joins
// HubNetwork.
type UpState struct {
	Version    int               `json:"version"`
	Project    string            `json:"project"`
	Workspace  string            `json:"workspace"`
	HubNetwork string            `json:"hub_network"`
	HubURL     string            `json:"hub_url"`
	HubKey     string            `json:"hub_key"`
	Locks      map[string]UpLock `json:"locks"`
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
}

// NewUpState is the contract for c, run as compose project project.
func NewUpState(c *Config, project, ws, hubKey string) UpState {
	s := UpState{Version: 1, Project: project, Workspace: ws, HubNetwork: project + "_lockhub",
		HubURL: "http://lockhub:8443", HubKey: hubKey, Locks: map[string]UpLock{}}
	for _, n := range c.Instances() {
		l := c.Locks[n]
		ul := UpLock{Type: l.Type, Profile: l.Profile, Socket: project + "_" + n + "-run", GID: Kinds[l.Type].GID}
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
	return writeFile(filepath.Join(d, UpFile), append(b, '\n'))
}
