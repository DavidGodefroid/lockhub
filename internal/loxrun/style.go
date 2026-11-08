package loxrun

import (
	"hash/fnv"
	"os"
	"regexp"
	"strings"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// Style is how lox run draws: colours (off with NO_COLOR or a dumb
// terminal), Unicode glyphs (off on a terminal that cannot draw them), and
// the background (light or dark) the colours are chosen for. Colours are
// the terminal's own 16 ANSI colours, which every theme maps to readable
// shades, plus bold, dim, italic and reverse.
type Style struct {
	Color   bool
	Unicode bool
	Light   bool
}

// DetectStyle is the style for this environment (lookup: os.LookupEnv):
// NO_COLOR (set, whatever its value) or TERM=dumb turn colour off;
// LC_ALL / LC_CTYPE / LANG naming a charset other than UTF-8, or the
// Linux console, turn Unicode off; theme ("light", "dark") or else
// COLORFGBG (set by many terminals) picks the background, dark by
// default.
func DetectStyle(lookup func(string) (string, bool), theme string) Style {
	if lookup == nil {
		lookup = os.LookupEnv
	}
	getenv := func(k string) string { v, _ := lookup(k); return v }
	st := Style{Color: true, Unicode: true}
	if _, ok := lookup("NO_COLOR"); ok || getenv("TERM") == "dumb" {
		st.Color = false
	}
	loc := getenv("LC_ALL")
	if loc == "" {
		loc = getenv("LC_CTYPE")
	}
	if loc == "" {
		loc = getenv("LANG")
	}
	if l := strings.ToLower(loc); l != "" && l != "c.utf-8" && !strings.Contains(l, "utf-8") && !strings.Contains(l, "utf8") {
		st.Unicode = false
	}
	if getenv("TERM") == "linux" {
		st.Unicode = false // the console font lacks most glyphs
	}
	switch theme {
	case "light":
		st.Light = true
	case "dark":
	default:
		// COLORFGBG is "fg;bg" (or "fg;default;bg"): a background of 7
		// or of a bright colour is light.
		if fb := getenv("COLORFGBG"); fb != "" {
			switch fb[strings.LastIndexByte(fb, ';')+1:] {
			case "7", "9", "10", "11", "12", "13", "14", "15":
				st.Light = true
			}
		}
	}
	return st
}

// SGR styles, by role. Light backgrounds keep the same roles with colours
// that stay readable there (no yellow text, no bright white).
const (
	sgrBold    = "1"
	sgrDim     = "2"
	sgrMasked  = "2;3"
	sgrReverse = "7"
)

func (st Style) auto() string { return "2;32" } // dim green
func (st Style) approved() string {
	return "32"
}
func (st Style) asked() string {
	if st.Light {
		return "1;33;7" // reverse: yellow text is unreadable on white
	}
	return "1;33"
}
func (st Style) denied() string  { return "31" }
func (st Style) errored() string { return "35" }
func (st Style) prod() string    { return "1;31" }
func (st Style) writeKind() string {
	if st.Light {
		return "1;35"
	}
	return "1;33"
}
func (st Style) ddlKind() string { return "1;31" }
func (st Style) keyword() string {
	if st.Light {
		return "1;34"
	}
	return "1;36"
}
func (st Style) writeKeyword() string { return st.writeKind() }
func (st Style) frame(prod bool) string {
	if prod {
		return "1;31"
	}
	if st.Light {
		return "1;35"
	}
	return "1;33"
}
func (st Style) badge(m Mode) string {
	if m == Manual {
		return "1;30;43" // black on yellow
	}
	return "1;30;42" // black on green
}
func (st Style) dim() string {
	return sgrDim
}

// agentColor is a stable colour per agent name.
func (st Style) agentColor(agent string) string {
	dark := []string{"36", "34", "35", "32", "33", "96", "94", "95"}
	light := []string{"36", "34", "35", "32", "31", "94", "95", "90"}
	pal := dark
	if st.Light {
		pal = light
	}
	h := fnv.New32a()
	h.Write([]byte(agent))
	return pal[h.Sum32()%uint32(len(pal))]
}

// glyphs.
func (st Style) g(uni, ascii string) string {
	if st.Unicode {
		return uni
	}
	return ascii
}

func (st Style) ellipsis() string { return st.g("…", "...") }

// lockIcon is a lock product's icon and short name.
func (st Style) lockIcon(lock string) string {
	switch lock {
	case "locksql":
		return st.g("◆", "S")
	case "lockmq":
		return st.g("◇", "Q")
	case "lockfile":
		return st.g("▤", "F")
	case "lockhttp":
		return st.g("⇄", "H")
	case "locklog":
		return st.g("≡", "L")
	case "lockssh":
		return st.g("❯", "R")
	}
	return st.g("●", "*")
}

// kindLabel is the short name of a ticket kind, 6 columns at most.
func kindLabel(k ticket.Kind) string {
	switch k {
	case ticket.KindConnect:
		return "conn"
	case ticket.KindEndpoint:
		return "route"
	case "":
		return "?"
	}
	return string(k)
}

func (st Style) kindStyle(k ticket.Kind) string {
	switch k {
	case ticket.KindWrite, ticket.KindAction:
		return st.writeKind()
	case ticket.KindDDL, ticket.KindPolicy:
		return st.ddlKind()
	case ticket.KindConnect, ticket.KindEndpoint:
		return st.keyword()
	}
	return ""
}

// masked matches the placeholders a lock's masking leaves (lockkit pii):
// "j***(20)", "<redacted>", "<redacted:ref>", "<masked bytes:N>".
var masked = regexp.MustCompile(`<redacted(?::[A-Za-z0-9._-]{1,64})?>|<masked bytes:\d+>|[^\s*()<>]?\*\*\*\(\d+\)`)

var sqlKeywords = map[string]bool{}
var sqlWrites = map[string]bool{}

func init() {
	for _, k := range strings.Fields(`SELECT FROM WHERE AND OR NOT IN IS NULL AS ON JOIN LEFT RIGHT INNER OUTER FULL CROSS
		GROUP BY ORDER HAVING LIMIT OFFSET DISTINCT UNION ALL EXISTS BETWEEN LIKE ILIKE CASE WHEN THEN ELSE END
		WITH RETURNING VALUES INTO SET ASC DESC COUNT SUM AVG MIN MAX EXPLAIN SHOW DESCRIBE USING`) {
		sqlKeywords[k] = true
	}
	for _, k := range strings.Fields(`INSERT UPDATE UPSERT DELETE MERGE TRUNCATE CREATE ALTER DROP RENAME GRANT REVOKE
		REPLACE COPY CALL DO PUBLISH PURGE POST PUT PATCH MOVE REMOVE WRITE`) {
		sqlWrites[k] = true
	}
	for _, k := range strings.Fields(`GET HEAD OPTIONS PEEK CONSUME READ LIST SEARCH TABLE INDEX VIEW SCHEMA`) {
		sqlKeywords[k] = true
	}
}

// highlight styles a masked request summary: keywords (SQL, HTTP
// methods, MQ and file verbs), writes standing out, masked placeholders
// set apart (dim italic, ‹ › around them) so clear text and masked
// values are told apart at a glance. base is the style of the rest.
func (st Style) highlight(s, base string) line {
	var l line
	open, closeG := st.g("‹", "<"), st.g("›", ">")
	rest := s
	for rest != "" {
		loc := masked.FindStringIndex(rest)
		chunk := rest
		if loc != nil {
			chunk = rest[:loc[0]]
		}
		l = append(l, st.words(chunk, base)...)
		if loc == nil {
			break
		}
		tok := rest[loc[0]:loc[1]]
		tok = strings.TrimSuffix(strings.TrimPrefix(tok, "<"), ">")
		l = l.add(open+tok+closeG, sgrMasked)
		rest = rest[loc[1]:]
	}
	return l
}

// words styles the keywords of a plain chunk.
func (st Style) words(s, base string) line {
	var l line
	start := 0
	flush := func(end int) {
		if end > start {
			l = l.add(s[start:end], base)
		}
	}
	i := 0
	for i < len(s) {
		c := s[i]
		if !isWordByte(c) {
			i++
			continue
		}
		j := i
		for j < len(s) && isWordByte(s[j]) {
			j++
		}
		w := strings.ToUpper(s[i:j])
		// A keyword is one in capitals, or the line's first word: "on" in
		// a sentence stays plain, "select" opening a query does not.
		if w != s[i:j] && strings.TrimSpace(s[:i]) != "" {
			w = ""
		}
		var sgr string
		switch {
		case sqlWrites[w]:
			sgr = st.writeKeyword()
		case sqlKeywords[w]:
			sgr = st.keyword()
		}
		if sgr != "" && (i == 0 || !isWordByte(s[i-1])) {
			flush(i)
			l = l.add(s[i:j], sgr)
			start = j
		}
		i = j
	}
	flush(len(s))
	return l
}

func isWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
