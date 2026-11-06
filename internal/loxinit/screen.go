package loxinit

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// The screens are pure: inputs to text, golden-tested.

// RenderPrereqs is the prerequisites screen.
func RenderPrereqs(w io.Writer, p Prereqs, goos string) {
	fmt.Fprintln(w, "Prerequisites")
	if p.Docker != "" {
		fmt.Fprintf(w, "  ok  Docker %s\n", p.Docker)
	} else {
		fmt.Fprintf(w, "  !!  Docker does not answer: %s\n", DockerHint(goos, p.DockerCLI))
	}
	if p.Cosign != "" {
		fmt.Fprintln(w, "  ok  cosign (lox add and lox run verify every image's signature)")
	} else {
		fmt.Fprintf(w, "  !!  cosign not found: %s\n", CosignHint(goos))
	}
	if p.Lea != "" {
		fmt.Fprintln(w, "  ok  lea")
	} else {
		fmt.Fprintf(w, "  --  lea not found (the locks run without it; lockhttp needs it): %s\n", LeaHint)
	}
	var have, miss []string
	for _, l := range Locks {
		if l == "locklog" {
			continue
		}
		if p.Launchers[l] != "" {
			have = append(have, l)
		} else {
			miss = append(miss, l)
		}
	}
	if len(have) > 0 {
		fmt.Fprintf(w, "  ok  launchers: %s\n", strings.Join(have, ", "))
	}
	if len(miss) > 0 {
		fmt.Fprintf(w, "  --  launchers not installed: %s (https://github.com/DavidGodefroid/<lock>#install)\n", strings.Join(miss, ", "))
	}
}

// RenderHints shows the data sources the project's files name, one line
// each with the files (never a key's value) and the lox add that serves
// it, then what to check first. Nothing when there is none.
func RenderHints(w io.Writer, sources []Source) {
	if len(sources) == 0 {
		return
	}
	fmt.Fprintln(w)
	for _, s := range sources {
		var files []string
		for _, f := range s.From {
			f, _, _ = strings.Cut(f, " (")
			if !slices.Contains(files, f) {
				files = append(files, f)
			}
		}
		fmt.Fprintf(w, "  found: %s on %s (%s) → `lox add %s`\n", s.Kind, s.Target(), strings.Join(files, ", "), s.Lock())
		for _, n := range s.Notes {
			fmt.Fprintf(w, "    note: %s\n", n)
		}
	}
}
