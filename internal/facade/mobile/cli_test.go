package mobile_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/family"
	"github.com/DavidGodefroid/lockhub/internal/mobilecli"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// lock mobile pair, list and revoke against the hub's facade socket: the
// device is pinned only once the human said yes at the terminal.
func TestLockMobilePair(t *testing.T) {
	for _, answer := range []string{"n", "y", "other origin"} {
		t.Run("answer "+answer, func(t *testing.T) {
			e := newEnv(t, route.Rules{})
			state := t.TempDir() + "/state"
			c := &mobilecli.Client{HTTP: e.facade}
			pr, pw := io.Pipe()
			done := make(chan error, 1)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			go func() {
				o := origin
				if answer == "other origin" {
					o = "https://other.example.net"
				}
				done <- mobilecli.Pair(ctx, c, "phone", o, state, bufio.NewReader(strings.NewReader(answer+"\n")), pw)
				pw.Close()
			}()
			sc := bufio.NewScanner(pr)
			var code string
			re := regexp.MustCompile(`^\s+([A-Z0-9]{4}) ([A-Z0-9]{4})$`)
			for sc.Scan() {
				if m := re.FindStringSubmatch(sc.Text()); m != nil {
					code = m[1] + m[2]
					break
				}
			}
			phone := e.phone("phone")
			fp, err := phone.Pair(code)
			if err != nil {
				t.Fatal(err)
			}
			var rest bytes.Buffer
			go io.Copy(&rest, pr)
			err = <-done
			devs, _ := family.ReadDevices(state)
			if answer != "y" {
				if err == nil || len(devs) != 0 {
					t.Fatalf("declined: %v, pinned %v", err, devs)
				}
				if phone.Login() == nil {
					t.Fatal("a declined device signs in")
				}
				return
			}
			if err != nil || len(devs) != 1 || devs[0].Name != "phone" {
				t.Fatalf("pair: %v, pinned %+v", err, devs)
			}
			if got, _ := devs[0].Fingerprint(); got != fp {
				t.Fatalf("pinned %s, the phone showed %s", got, fp)
			}
			if err := phone.Login(); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := mobilecli.List(ctx, c, state, &out); err != nil || !strings.HasSuffix(strings.TrimSpace(out.String()), "  pinned") {
				t.Fatalf("list: %v %s", err, out.String())
			}
			if err := mobilecli.Revoke(ctx, c, "phone", state, &out); err != nil {
				t.Fatal(err)
			}
			if devs, _ := family.ReadDevices(state); len(devs) != 0 {
				t.Fatalf("still pinned after revoke: %+v", devs)
			}
			if _, err := phone.Queue(); err == nil {
				t.Fatal("a revoked device still has its session")
			}
		})
	}
}
