package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/DavidGodefroid/lockhub/internal/family"
)

const downUsage = "usage: lox down [--file lockfamily.yaml]"

// downCmd is lox down: the workspace's stack stopped (the hub, the locks,
// their gateways: containers and networks), its volumes and lox run's
// state kept. Nothing running is not an error: lox down again does
// nothing.
func downCmd(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	fs.SetOutput(stderr)
	file := fs.String("file", "", "the workspace's lockfamily.yaml (default: .lockfamily/lockfamily.yaml, or a legacy ./lockfamily.yaml)")
	pos, err := parse(fs, args)
	if err != nil {
		return 2
	}
	if len(pos) != 0 {
		fmt.Fprintln(stderr, downUsage)
		return 2
	}
	abs, err := lockFile(*file, stderr)
	if err != nil {
		fmt.Fprintln(stderr, "lox down:", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	project := family.Project(family.Workspace(abs))
	return down(ctx, family.Exec{Stderr: stderr}, project, stdout, stderr)
}

func down(ctx context.Context, run family.Runner, project string, stdout, stderr io.Writer) int {
	ctrs, nets, err := family.StopStack(ctx, run, project)
	if err != nil {
		fmt.Fprintln(stderr, "lox down:", err)
		return 1
	}
	if ctrs == 0 && nets == 0 {
		fmt.Fprintf(stdout, "lox down: nothing runs for this workspace (project %s)\n", project)
		return 0
	}
	fmt.Fprintf(stdout, "lox down: stopped %d container(s) and removed %d network(s) of project %s; volumes and the state directory kept: lox run starts it again\n", ctrs, nets, project)
	return 0
}
