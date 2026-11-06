package loxrun

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// seg is a run of text with one SGR style ("" plain). Every line lox run
// draws is built of segs: its width is measured on the text alone, it is
// cut and padded there, and the escapes are added last (or not at all,
// without colour).
type seg struct{ s, sgr string }

type line []seg

func (l line) add(s, sgr string) line { return append(l, seg{s, sgr}) }

// text is l's text without style.
func (l line) text() string {
	var b strings.Builder
	for _, s := range l {
		b.WriteString(s.s)
	}
	return b.String()
}

func (l line) width() int {
	n := 0
	for _, s := range l {
		n += strWidth(s.s)
	}
	return n
}

// trunc cuts l to w columns, ending in ell when it cut.
func (l line) trunc(w int, ell string) line {
	if l.width() <= w {
		return l
	}
	ew := strWidth(ell)
	if w < ew {
		ell, ew = "", 0
	}
	room := w - ew
	var out line
	lastSGR := ""
	for _, s := range l {
		sw := strWidth(s.s)
		if sw <= room {
			out = append(out, s)
			room -= sw
			lastSGR = s.sgr
			continue
		}
		cut := cutWidth(s.s, room)
		if cut != "" {
			out = append(out, seg{cut, s.sgr})
		}
		lastSGR = s.sgr
		break
	}
	if ell != "" {
		out = append(out, seg{ell, lastSGR})
	}
	return out
}

// pad pads l with spaces to w columns (cutting it first if wider).
func (l line) pad(w int, ell string) line {
	l = l.trunc(w, ell)
	if n := w - l.width(); n > 0 {
		l = append(l, seg{strings.Repeat(" ", n), ""})
	}
	return l
}

// padLeft is pad with the spaces first (right-aligned).
func (l line) padLeft(w int, ell string) line {
	l = l.trunc(w, ell)
	if n := w - l.width(); n > 0 {
		l = append(line{{strings.Repeat(" ", n), ""}}, l...)
	}
	return l
}

// render writes l with its styles when color, plain otherwise.
func (l line) render(color bool) string {
	var b strings.Builder
	for _, s := range l {
		if color && s.sgr != "" && s.s != "" {
			b.WriteString("\x1b[" + s.sgr + "m" + s.s + "\x1b[0m")
			continue
		}
		b.WriteString(s.s)
	}
	return b.String()
}

// runeWidth is the terminal columns of r: 0 for combining marks and
// zero-width characters, 2 for wide (East Asian, emoji) ones.
func runeWidth(r rune) int {
	switch {
	case r == 0, unicode.Is(unicode.Mn, r), unicode.Is(unicode.Me, r), unicode.Is(unicode.Cf, r):
		return 0
	case r < 0x1100:
		return 1
	case r <= 0x115F, r == 0x2329, r == 0x232A,
		r >= 0x2E80 && r <= 0xA4CF && r != 0x303F,
		r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0xFE30 && r <= 0xFE4F,
		r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6,
		r >= 0x1F300 && r <= 0x1F64F,
		r >= 0x1F900 && r <= 0x1F9FF,
		r >= 0x20000 && r <= 0x3FFFD:
		return 2
	}
	return 1
}

func strWidth(s string) int {
	n := 0
	for _, r := range s {
		n += runeWidth(r)
	}
	return n
}

// cutWidth is the longest prefix of s within w columns.
func cutWidth(s string, w int) string {
	n := 0
	for i, r := range s {
		rw := runeWidth(r)
		if n+rw > w {
			return s[:i]
		}
		n += rw
	}
	return s
}

// asciiOnly replaces what a terminal without Unicode cannot draw.
func asciiOnly(s string) string {
	if isASCII(s) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if r < utf8.RuneSelf {
			b.WriteRune(r)
			continue
		}
		switch r {
		case '…':
			b.WriteString("...")
		case '‹':
			b.WriteByte('<')
		case '›':
			b.WriteByte('>')
		case '·':
			b.WriteByte('-')
		case '×':
			b.WriteByte('x')
		case '—', '─', '━':
			b.WriteByte('-')
		default:
			b.WriteByte('?')
		}
	}
	return b.String()
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}
