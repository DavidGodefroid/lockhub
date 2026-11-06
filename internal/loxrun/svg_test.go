package loxrun

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DavidGodefroid/lockkit/ticket"
)

// The README's pictures of lox run are drawn by the renderer itself (an
// animated session on a dark terminal, a still on a light one): a change
// of the rendering that is not in docs/ fails here; -update redraws them.
func TestReadmeSVG(t *testing.T) {
	for _, c := range []struct {
		file  string
		st    Style
		views []View
	}{
		{"lox-run.svg", Style{Color: true, Unicode: true}, demoSession()},
		{"lox-run-light.svg", Style{Color: true, Unicode: true, Light: true}, []View{sampleView()}},
	} {
		got := svg(c.views, 100, 26, c.st)
		path := filepath.Join("..", "..", "docs", c.file)
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		want, err := os.ReadFile(path)
		if err != nil || string(want) != got {
			t.Errorf("%s is not what the renderer draws (go test ./internal/loxrun -update): %v", path, err)
		}
	}
}

// demoSession is a short session: the first request asks for the
// connection, reads run on their own, a production write is asked.
func demoSession() []View {
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	base := View{Workspace: "~/Documents/shop", Mode: Auto, HubOK: true, Locks: 2, Loc: time.UTC}
	connCard := Card{ID: "c1", Instance: "shop", Lock: "locksql", Agent: "dev-1", Profile: "prod", Kind: ticket.KindConnect, Production: true,
		Header: "prod · connect", Body: []string{"endpoint: db.internal:5432/shop", "credentials: ask", "secret: typed on the decider, sealed to the lock"},
		Warnings: []string{"production"}, Why: "first connection to this profile in this session", Expires: at(600)}
	conn := Entry{At: at(2), Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindConnect,
		Summary: "connect db.internal:5432/shop (credentials: ask)", Status: Waiting}
	reads := func(n int) Entry {
		return Entry{At: at(10 + n), Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindRead,
			Summary: "SELECT id, total FROM orders WHERE customer = c***(8)", Target: "orders", Status: AutoApproved, Rule: "default:read", Result: ResRan, Count: n}
	}
	mq := Entry{At: at(30), Agent: "worker", Instance: "events", Lock: "lockmq", Profile: "local", Kind: ticket.KindAction,
		Summary: "PEEK orders.created (10 messages)", Status: AutoApproved, Rule: "default:action", Result: ResRan}
	upd := Entry{At: at(41), Agent: "dev-1", Instance: "shop", Lock: "locksql", Profile: "prod", Production: true, Kind: ticket.KindWrite,
		Summary: "UPDATE customers SET email = j***(20) WHERE id = 4***(3)", Status: Waiting}
	updCard := Card{ID: "u1", Instance: "shop", Lock: "locksql", Agent: "dev-1", Profile: "prod", Kind: ticket.KindWrite, Production: true,
		Header: "shop / prod · write", Body: []string{"UPDATE customers SET email = j***(20) WHERE id = 4***(3)", "-- 1 row (estimated)"},
		Warnings: []string{"production"}, Touched: []string{"email"}, Why: "write is always asked", Expires: at(641)}

	var out []View
	v := base
	v.Now = at(1)
	out = append(out, v)

	v = base
	v.Now = at(3)
	v.Cards = []Card{connCard}
	v.Feed = []Entry{conn}
	out = append(out, v)

	v.Cards[0].Prompt = &Prompt{Label: "password for shop/prod:", Secret: true, Typed: []rune("correct-horse")}
	out = append(out, v)

	conn.Status, conn.Result = Approved, ResRan
	v = base
	v.Now = at(40)
	v.Profiles = []ProfileConn{{Name: "shop/prod", Since: at(5), Production: true}}
	v.Feed = []Entry{conn, reads(12), mq}
	out = append(out, v)

	v.Now = at(42)
	v.Cards = []Card{updCard}
	v.Feed = append(v.Feed, upd)
	out = append(out, v)

	upd.Status, upd.Result = Approved, ResRan
	v.Now = at(50)
	v.Cards = nil
	v.Feed = []Entry{conn, reads(12), mq, upd, reads(3)}
	out = append(out, v)

	v.Mode = Manual
	v.Flash = "MANUAL mode: every ticket is asked"
	out = append(out, v)
	return out
}

// svgPalette maps the 16 ANSI colours of a terminal theme.
type svgPalette struct {
	bg, fg string
	ansi   [16]string
}

var (
	darkPalette = svgPalette{bg: "#1e2127", fg: "#d7dae0", ansi: [16]string{
		"#3f4451", "#e06c75", "#98c379", "#e5c07b", "#61afef", "#c678dd", "#56b6c2", "#d7dae0",
		"#4f5666", "#ff7b86", "#b1e18b", "#efd38b", "#67cdff", "#e48bff", "#63d4e0", "#ffffff"}}
	lightPalette = svgPalette{bg: "#fafafa", fg: "#383a42", ansi: [16]string{
		"#383a42", "#e45649", "#40a14f", "#c18401", "#0184bc", "#a626a4", "#0997b3", "#d4d4d4",
		"#a0a1a7", "#ff6b5f", "#50c45f", "#e0a102", "#21a4e6", "#c43ec2", "#14b3d4", "#ffffff"}}
)

// svg draws frames as an SVG terminal, animated when there are several.
func svg(frames []View, w, h int, st Style) string {
	pal := darkPalette
	if st.Light {
		pal = lightPalette
	}
	const cw, lh, pad = 8.4, 18.0, 14.0
	width, height := pad*2+cw*float64(w), pad*2+lh*float64(h)+22
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" viewBox="0 0 %.0f %.0f" font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="14">`+"\n", width, height, width, height)
	n := len(frames)
	const per = 2.6 // seconds per frame
	b.WriteString("<style>text{white-space:pre}")
	if n > 1 {
		total := per * float64(n)
		for i := range frames {
			from, to := float64(i)/float64(n)*100, float64(i+1)/float64(n)*100
			fmt.Fprintf(&b, "@keyframes f%d{0%%,%.3f%%{opacity:0}%.3f%%,%.3f%%{opacity:1}%.3f%%,100%%{opacity:0}}", i, max(from-0.001, 0), from, to-0.001, to)
			fmt.Fprintf(&b, ".f%d{opacity:0;animation:f%d %.1fs step-end infinite}", i, i, total)
		}
	}
	b.WriteString("</style>\n")
	fmt.Fprintf(&b, `<rect width="100%%" height="100%%" rx="8" fill="%s"/>`+"\n", pal.bg)
	for i, c := range []string{"#ff5f57", "#febc2e", "#28c840"} {
		fmt.Fprintf(&b, `<circle cx="%d" cy="13" r="5" fill="%s"/>`, 18+i*16, c)
	}
	fmt.Fprintf(&b, `<text x="%.0f" y="17" fill="%s" font-size="12" text-anchor="middle" opacity="0.6">lox run</text>`+"\n", width/2, pal.fg)
	for i, v := range frames {
		cls := ""
		if n > 1 {
			cls = fmt.Sprintf(` class="f%d"`, i)
		}
		fmt.Fprintf(&b, "<g%s>\n", cls)
		for row, l := range frameLines(v, w, h, st) {
			y := 22 + pad + lh*float64(row)
			col := 0
			for _, s := range l {
				if s.s == "" {
					continue
				}
				a := parseSGR(s.sgr)
				fg, bg := pal.fg, ""
				if a.fg >= 0 {
					fg = pal.ansi[a.fg]
				}
				if a.bg >= 0 {
					bg = pal.ansi[a.bg]
				}
				if a.reverse {
					if bg == "" {
						bg = pal.bg
					}
					fg, bg = bg, fg
				}
				sw := strWidth(s.s)
				x := pad + cw*float64(col)
				if bg != "" {
					fmt.Fprintf(&b, `<rect x="%.1f" y="%.1f" width="%.1f" height="%.0f" fill="%s"/>`, x, y-lh+4, cw*float64(sw), lh, bg)
				}
				if strings.TrimSpace(s.s) != "" {
					attrs := ""
					if a.bold {
						attrs += ` font-weight="bold"`
					}
					if a.italic {
						attrs += ` font-style="italic"`
					}
					if a.dim {
						attrs += ` opacity="0.6"`
					}
					fmt.Fprintf(&b, `<text x="%.1f" y="%.1f" fill="%s"%s textLength="%.1f" lengthAdjust="spacingAndGlyphs">%s</text>`,
						x, y, fg, attrs, cw*float64(sw), html.EscapeString(s.s))
				}
				col += sw
			}
			b.WriteString("\n")
		}
		b.WriteString("</g>\n")
	}
	b.WriteString("</svg>\n")
	return b.String()
}

type sgrAttrs struct {
	bold, dim, italic, reverse bool
	fg, bg                     int
}

func parseSGR(s string) sgrAttrs {
	a := sgrAttrs{fg: -1, bg: -1}
	for _, p := range strings.Split(s, ";") {
		n, err := strconv.Atoi(p)
		if err != nil {
			continue
		}
		switch {
		case n == 1:
			a.bold = true
		case n == 2:
			a.dim = true
		case n == 3:
			a.italic = true
		case n == 7:
			a.reverse = true
		case n >= 30 && n <= 37:
			a.fg = n - 30
		case n >= 90 && n <= 97:
			a.fg = n - 90 + 8
		case n >= 40 && n <= 47:
			a.bg = n - 40
		}
	}
	return a
}
