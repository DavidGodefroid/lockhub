package family

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// upReview runs lox up in w's workspace with the given options.
func upReview(w ws, ctx context.Context, in io.Reader, review bool, f *fake) (string, error) {
	var out strings.Builder
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000",
		Run: f, In: bufio.NewReader(in), Out: &out, Review: review}
	err := u.Do(ctx)
	return out.String(), err
}

func TestHubOnlyFirstUpAsksNothing(t *testing.T) {
	w := newWS(t, hubOnly)
	f := newFake()
	out, err := upReview(w, context.Background(), strings.NewReader(""), false, f)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if strings.Contains(out, "Apply? [y/N]") {
		t.Errorf("asked a question:\n%s", out)
	}
	if !strings.Contains(out, "Hub only, no lock: nothing can reach a credential yet; applied without a question (--review shows everything and asks)") {
		t.Errorf("no notice:\n%s", out)
	}
	if !f.ran("up -d") {
		t.Errorf("not applied: %v", f.calls)
	}
}

func TestHubOnlyReviewFlagAsks(t *testing.T) {
	w := newWS(t, hubOnly)
	f := newFake()
	out, err := upReview(w, context.Background(), strings.NewReader("n\n"), true, f)
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "Apply? [y/N]") || f.ran("up -d") {
		t.Errorf("--review: %v %v\n%s", err, f.calls, out)
	}
}

func TestRemoveLastLockStillAsks(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	if _, err := w.up("y\n", f); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(w.file, []byte(hubOnly), 0o644)
	f2 := &fake{keys: f.keys}
	out, err := upReview(w, context.Background(), strings.NewReader("n\n"), false, f2)
	if !errors.Is(err, ErrNotConfirmed) || !strings.Contains(out, "- lock crm-prod type locksql") || f2.ran("up -d") {
		t.Errorf("removing the last lock: %v %v\n%s", err, f2.calls, out)
	}
}

func TestUpInterruptedAtReviewAppliesNothing(t *testing.T) {
	w := newWS(t, yamlConf(""))
	f := newFake()
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	var out strings.Builder
	var mu sync.Mutex
	u := &Up{File: w.file, State: filepath.Join(w.dir, "state"), Runtime: filepath.Join(w.dir, "run"), User: "1000:1000",
		Run: f, In: bufio.NewReader(pr), Out: &lockedWriter{&mu, &out}}
	// Cancel only once the review is on screen and waiting for the answer.
	go func() {
		for {
			mu.Lock()
			asked := strings.Contains(out.String(), "Apply? [y/N]")
			mu.Unlock()
			if asked {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	err := u.Do(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
	if f.ran("up -d") {
		t.Errorf("applied: %v", f.calls)
	}
	if _, err := os.Stat(filepath.Join(w.dir, "state", "applied.json")); err == nil {
		t.Error("applied.json written")
	}
}

// lockedWriter lets a test read the output while Up is still writing it.
type lockedWriter struct {
	mu *sync.Mutex
	b  *strings.Builder
}

func (w *lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
