package family

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

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
	// 0644: the lock containers read it through a read-only bind mount.
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
