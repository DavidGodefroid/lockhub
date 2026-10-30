package family

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// DevicesFile is the pinned devices of a workspace (lockkit
// ticket.DeviceSet), in lock up's private state directory: never in the
// workspace, which agents can write. `lock mobile pair` adds the device the
// human confirmed at the terminal; `lock mobile revoke` removes one; lock
// up reviews the change and mounts the file read-only in every lock.
func DevicesFile(state string) string { return filepath.Join(state, "devices.json") }

// ReadDevices reads the pinned devices; none when the file is missing.
func ReadDevices(state string) ([]ticket.Device, error) {
	b, err := os.ReadFile(DevicesFile(state))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return ticket.ParseDevices(b)
}

func writeDevices(state string, devs []ticket.Device) error {
	if err := privateDir(state); err != nil {
		return err
	}
	b, err := ticket.MarshalDevices(devs)
	if err != nil {
		return err
	}
	tmp := DevicesFile(state) + ".tmp"
	// 0644 like the snapshots: the lock containers mount a reviewed
	// snapshot of it (devicesSnapshot), never this live file.
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, DevicesFile(state))
}

// PinDevice adds dev to the pinned devices (replacing one of the same
// name).
func PinDevice(state string, dev ticket.Device) error {
	if err := dev.Validate(); err != nil {
		return err
	}
	devs, err := ReadDevices(state)
	if err != nil {
		return err
	}
	var out []ticket.Device
	for _, d := range devs {
		if d.ID != dev.ID && d.Name != dev.Name {
			out = append(out, d)
		}
	}
	out = append(out, dev)
	if len(out) > ticket.MaxDevices {
		return fmt.Errorf("at most %d devices: revoke one first", ticket.MaxDevices)
	}
	return writeDevices(state, out)
}

// UnpinDevice removes device id; it reports whether it was pinned.
func UnpinDevice(state, id string) (bool, error) {
	devs, err := ReadDevices(state)
	if err != nil {
		return false, err
	}
	var out []ticket.Device
	found := false
	for _, d := range devs {
		if d.ID == id {
			found = true
			continue
		}
		out = append(out, d)
	}
	if !found {
		return false, nil
	}
	return true, writeDevices(state, out)
}

// devicesSummary is the review lines of the pinned devices.
func devicesSummary(devs []ticket.Device) []string {
	var s []string
	for _, d := range devs {
		fp, _ := d.Fingerprint()
		s = append(s, fmt.Sprintf("device %s %s fingerprint %s", d.Name, d.ID, fp))
	}
	return s
}

// devicesSnapshot is the reviewed set of devices, written once lock up is
// confirmed under a name of its own content: the locks mount that file,
// never the live one, which lock mobile may change in between.
func devicesSnapshot(state string, devs []ticket.Device) (path string, content []byte, err error) {
	b, err := ticket.MarshalDevices(devs)
	if err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(b)
	return filepath.Join(state, "devices-"+hex.EncodeToString(sum[:8])+".json"), b, nil
}

// AppliedMobileOrigin is hub.mobile.origin as the last confirmed lock up
// applied it (lock up's private state, not the workspace's yaml, which
// agents can write).
func AppliedMobileOrigin(state string) (string, error) {
	b, err := os.ReadFile(filepath.Join(state, "applied.json"))
	if err != nil {
		return "", fmt.Errorf("no applied configuration (run lock up first): %w", err)
	}
	var a Applied
	if err := json.Unmarshal(b, &a); err != nil {
		return "", err
	}
	for _, l := range a.Summary {
		if rest, ok := strings.CutPrefix(l, "hub mobile origin "); ok {
			if o, _, ok := strings.Cut(rest, " on "); ok {
				return o, nil
			}
		}
	}
	return "", errors.New("the applied configuration has no mobile facade (hub.mobile, then lock up)")
}
