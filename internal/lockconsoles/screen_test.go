package lockconsoles

import (
	"slices"
	"testing"
)

func TestScreen(t *testing.T) {
	var s screen
	s.Write([]byte("\x1b[1;31mPRODUCTION\x1b[0m profile shop-prod\r\n"))
	s.Write([]byte("progress 10%\rprogress 100%\n"))
	s.Write([]byte("typed: abcdef\r\x1b[Kerased\r\n"))
	// A status row drawn with the cursor saved: not a line of the screen.
	s.Write([]byte("\x1b7\x1b[40;1H\x1b[2Kidle in 9 min\x1b8"))
	s.Write([]byte("\x1b]0;title\x07  limits.idle_timeout  10m \xe2\x86"))
	s.Write([]byte("\x92 60m\n\n"))
	s.Write([]byte("Apply these changes? [y/N] "))
	got := s.Last(10)
	want := []string{"PRODUCTION profile shop-prod", "progress 100%", "erased", "  limits.idle_timeout  10m → 60m"}
	if !slices.Equal(got, want) {
		t.Fatalf("Last: %q\nwant %q", got, want)
	}
	s.Mark()
	if got := s.Last(10); len(got) != 0 {
		t.Fatalf("after Mark: %q", got)
	}
	// A control character or an escape in a printed line never reaches
	// lox run's screen.
	s.Write([]byte("a\x07b\x1b[2Jc\x01\n"))
	if got := s.Last(1); !slices.Equal(got, []string{"abc"}) {
		t.Fatalf("controls: %q", got)
	}
}

func TestContextOf(t *testing.T) {
	ls := []string{"a", "Password for x:"}
	if got := contextOf(ls, "Password for x:"); !slices.Equal(got, []string{"a"}) {
		t.Fatalf("%q", got)
	}
}
