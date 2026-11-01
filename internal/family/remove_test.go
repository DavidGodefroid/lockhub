package family

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// lox init's manual mode: a declared lock unchecked leaves lockfamily.yaml
// (and hub.routing), the rest of the file as it was.
func TestRemoveLock(t *testing.T) {
	w := newWS(t, "# my workspace\n"+yamlConf("  routing:\n    events: [tty]\n"))
	if err := RemoveLock(w.file, "events"); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.file)
	if !strings.Contains(string(b), "# my workspace") {
		t.Errorf("comment lost:\n%s", b)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Instances(), []string{"crm-prod"}) || len(c.Hub.Routing) != 0 {
		t.Errorf("locks %v, routing %v", c.Instances(), c.Hub.Routing)
	}
	if err := RemoveLock(w.file, "nope"); err == nil {
		t.Error("removed a lock that is not there")
	}
}

// The only lock may go: a hub alone is a valid lockfamily.yaml.
func TestRemoveLastLock(t *testing.T) {
	w := newWS(t, "version: 1\nhub:\n  image: "+hubImg+"\nlocks:\n  crm-prod:\n    type: locksql\n    image: "+sqlImg+"\n")
	if err := RemoveLock(w.file, "crm-prod"); err != nil {
		t.Fatal(err)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Locks) != 0 {
		t.Errorf("locks %v", c.Instances())
	}
}

// lox init gives lea's uid to the locks lea's agents reach.
func TestAddAllowedUIDs(t *testing.T) {
	w := newWS(t, yamlConf(""))
	if err := Add(w.file, AddOptions{Type: "lockfile", Name: "docs", Image: fileImg, Profile: "docs", AllowedUIDs: []int{1000}}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(w.file)
	if !strings.Contains(string(b), "    allowed_uids: [1000]\n") {
		t.Errorf("allowed_uids not written in flow style:\n%s", b)
	}
	c, err := Load(w.file)
	if err != nil {
		t.Fatal(err)
	}
	if l := c.Locks["docs"]; !slices.Equal(l.AllowedUIDs, UIDList{1000}) || l.Profile != "docs" {
		t.Errorf("added %+v", l)
	}
	// Refused as lox up would: the console's own uid.
	if err := Add(w.file, AddOptions{Type: "locksql", Name: "other", Image: sqlImg, AllowedUIDs: []int{10001}}); err == nil {
		t.Error("allowed_uids with the console's own uid accepted")
	}
}
