package loxrun

import (
	"unicode/utf8"
)

// KeyCode is a key that is not a printable character.
type KeyCode int

// Keys.
const (
	KeyRune KeyCode = iota
	KeyEnter
	KeyEsc
	KeyBackspace
	KeyTab
	KeyShiftTab
	KeyCtrlC
	KeyCtrlD
	KeyUnknown
	KeyUp
	KeyDown
)

// Key is one key press: Code, and Rune for KeyRune.
type Key struct {
	Code KeyCode
	Rune rune
}

// R is the key of a character.
func R(r rune) Key { return Key{Code: KeyRune, Rune: r} }

// ParseKeys splits what a terminal in raw mode sent into keys. Shift+Tab
// is CSI Z (ESC [ Z), the up and down arrows CSI or SS3 A and B; other
// escape sequences (other arrows, function keys) are KeyUnknown; an ESC alone at the end of b is Esc (a terminal sends a
// sequence in one write).
func ParseKeys(b []byte) []Key {
	var out []Key
	for len(b) > 0 {
		c := b[0]
		switch {
		case c == 0x1b:
			if len(b) == 1 {
				out = append(out, Key{Code: KeyEsc})
				b = b[1:]
				continue
			}
			if b[1] == '[' || b[1] == 'O' {
				// CSI / SS3: parameters, then a final byte 0x40-0x7e.
				i := 2
				for i < len(b) && (b[i] < 0x40 || b[i] > 0x7e) {
					i++
				}
				if i >= len(b) {
					out = append(out, Key{Code: KeyUnknown})
					return out
				}
				switch {
				case b[1] == '[' && i == 2 && b[i] == 'Z':
					out = append(out, Key{Code: KeyShiftTab})
				case i == 2 && b[i] == 'A':
					out = append(out, Key{Code: KeyUp})
				case i == 2 && b[i] == 'B':
					out = append(out, Key{Code: KeyDown})
				default:
					out = append(out, Key{Code: KeyUnknown})
				}
				b = b[i+1:]
				continue
			}
			out = append(out, Key{Code: KeyEsc})
			b = b[1:]
		case c == '\r' || c == '\n':
			out = append(out, Key{Code: KeyEnter})
			b = b[1:]
			if c == '\r' && len(b) > 0 && b[0] == '\n' {
				b = b[1:]
			}
		case c == 0x7f || c == 0x08:
			out = append(out, Key{Code: KeyBackspace})
			b = b[1:]
		case c == '\t':
			out = append(out, Key{Code: KeyTab})
			b = b[1:]
		case c == 0x03:
			out = append(out, Key{Code: KeyCtrlC})
			b = b[1:]
		case c == 0x04:
			out = append(out, Key{Code: KeyCtrlD})
			b = b[1:]
		case c < 0x20:
			out = append(out, Key{Code: KeyUnknown})
			b = b[1:]
		default:
			r, n := utf8.DecodeRune(b)
			if r == utf8.RuneError && n <= 1 {
				out = append(out, Key{Code: KeyUnknown})
				b = b[1:]
				continue
			}
			out = append(out, R(r))
			b = b[n:]
		}
	}
	return out
}
