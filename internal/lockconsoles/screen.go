package lockconsoles

import (
	"strings"
	"unicode/utf8"

	"github.com/DavidGodefroid/lockkit/sanitize"
)

// maxLines is how many of a console's last lines a screen keeps.
const maxLines = 40

// maxLine cuts a line that never ends (a console never prints one).
const maxLine = 512

// screen turns a console's terminal output into its last lines of text:
// escape sequences dropped, a
// status row drawn with a saved cursor (ESC 7 … ESC 8) left out, a carriage
// return going back to the line's start (what follows overwrites it) and
// an erase in line (ESC [ K) erasing. It keeps
// what the console printed only, never what is typed: lox run's pty does
// not echo, and the console echoes no secret.
type screen struct {
	lines []string
	cur   []rune
	col   int // the cursor in cur
	// esc is the escape sequence being read (ESC excluded), inEsc whether
	// one is.
	esc   []byte
	inEsc bool
	// saved: between ESC 7 and ESC 8 (a status row): dropped.
	saved bool
	// pending holds the bytes of a UTF-8 rune cut between two writes.
	pending []byte
	// fresh are the lines ended since the last Take (the per-lock feed);
	// row the status row being drawn, status the last one drawn and
	// statusSet whether it changed since the last Take.
	fresh     []string
	row       []rune
	status    string
	statusSet bool
}

// maxFresh bounds the lines kept between two Takes.
const maxFresh = 400

// Write takes output bytes; it never fails.
func (s *screen) Write(p []byte) (int, error) {
	n := len(p)
	if len(s.pending) > 0 {
		p = append(s.pending, p...)
		s.pending = nil
	}
	for len(p) > 0 {
		b := p[0]
		if s.inEsc {
			p = p[1:]
			s.escByte(b)
			continue
		}
		if b == 0x1b {
			s.inEsc, s.esc = true, s.esc[:0]
			p = p[1:]
			continue
		}
		if b < utf8.RuneSelf {
			p = p[1:]
			s.ctl(rune(b))
			continue
		}
		if !utf8.FullRune(p) {
			s.pending = append([]byte(nil), p...)
			break
		}
		r, size := utf8.DecodeRune(p)
		p = p[size:]
		s.ctl(r)
	}
	return n, nil
}

// escByte reads one byte of an escape sequence: CSI (ESC [ … final),
// OSC (ESC ] … BEL or ESC \), or a two-byte one (ESC 7, ESC 8, ESC c…).
func (s *screen) escByte(b byte) {
	s.esc = append(s.esc, b)
	switch s.esc[0] {
	case '[':
		if len(s.esc) > 1 && b >= 0x40 && b <= 0x7e {
			s.inEsc = false
			if b == 'K' && !s.saved {
				if string(s.esc) == "[2K" || string(s.esc) == "[1K" {
					s.cur, s.col = s.cur[:0], 0
				} else {
					s.cur = s.cur[:min(s.col, len(s.cur))]
				}
			}
		}
	case ']':
		if b == 0x07 || (b == '\\' && len(s.esc) > 1 && s.esc[len(s.esc)-2] == 0x1b) {
			s.inEsc = false
		}
	default:
		s.inEsc = false
		switch b {
		case '7':
			s.saved, s.row = true, s.row[:0]
		case '8':
			s.saved = false
			// The console clears it and sets its scroll region the same
			// way: only a row with text is its status.
			if r := strings.TrimSpace(string(s.row)); r != "" && r != s.status {
				s.status, s.statusSet = r, true
			}
		}
	}
	if len(s.esc) > 64 {
		s.inEsc = false // not a sequence a console writes: dropped
	}
}

func (s *screen) ctl(r rune) {
	if s.saved {
		if r >= 0x20 && r != 0x7f && len(s.row) < maxLine {
			s.row = append(s.row, r)
		}
		return
	}
	switch r {
	case '\n':
		s.endLine()
	case '\r':
		s.col = 0
	case '\b':
		s.col = max(s.col-1, 0)
	case '\t':
		s.put(' ')
	default:
		if r < 0x20 || r == 0x7f {
			return // the bell and the other control characters
		}
		s.put(r)
	}
}

// put writes r at the cursor.
func (s *screen) put(r rune) {
	switch {
	case s.col < len(s.cur):
		s.cur[s.col] = r
	case len(s.cur) < maxLine:
		s.cur = append(s.cur, r)
	default:
		return
	}
	s.col++
}

func (s *screen) endLine() {
	s.lines = append(s.lines, string(s.cur))
	s.fresh = append(s.fresh, string(s.cur))
	if len(s.fresh) > maxFresh {
		s.fresh = s.fresh[len(s.fresh)-maxFresh:]
	}
	s.cur, s.col = s.cur[:0], 0
	if len(s.lines) > maxLines {
		s.lines = s.lines[len(s.lines)-maxLines:]
	}
}

// Last returns up to n of the last lines printed, the line being written
// (a prompt) excluded, each one cleaned for a terminal, the empty lines
// at both ends dropped.
func (s *screen) Last(n int) []string {
	ls := s.lines
	if len(ls) > n {
		ls = ls[len(ls)-n:]
	}
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, strings.TrimRight(sanitize.Terminal(l, false), " "))
	}
	for len(out) > 0 && strings.TrimSpace(out[0]) == "" {
		out = out[1:]
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	return out
}

// Mark forgets the lines printed so far, the prompt being answered with
// them: Last then returns only what came after (the screen above the
// next question).
func (s *screen) Mark() {
	s.lines, s.cur, s.col = s.lines[:0], s.cur[:0], 0
}

// Take returns the lines ended since the last Take, each one cleaned for
// a terminal, and the status row when it changed (set).
func (s *screen) Take() (lines []string, status string, set bool) {
	for _, l := range s.fresh {
		lines = append(lines, strings.TrimRight(sanitize.Terminal(l, false), " "))
	}
	s.fresh = nil
	status, set = sanitize.Terminal(s.status, false), s.statusSet
	s.statusSet = false
	return lines, status, set
}
