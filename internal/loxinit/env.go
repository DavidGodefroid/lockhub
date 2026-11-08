package loxinit

import (
	"context"
	"os/exec"
	"strings"
)

// Locks are the lock types lox init knows, in the order its prerequisites
// screen lists their launchers.
var Locks = []string{"locksql", "lockmq", "lockfile", "lockhttp", "locklog", "lockssh"}

// Env is what lox init finds on the machine. Tests give their own.
type Env struct {
	// GOOS is the operating system (runtime.GOOS).
	GOOS string
	// LookPath finds a command (exec.LookPath).
	LookPath func(string) (string, error)
	// DockerVersion is the version of the Docker engine that answers.
	DockerVersion func(ctx context.Context) (string, error)
	// Types are the lock types lox up runs (family.Types).
	Types []string
	// UID is the uid lea's agents run as (os.Getuid).
	UID int
	// HostLogs are this host's log directories locklog reads
	// (HostLogDirs); nil: none.
	HostLogs func() []string
	// SSHHosts are the SSH hosts lockssh could serve (SSHHosts of the
	// user's ~/.ssh/config); nil: none.
	SSHHosts func() []Source
}

// RealDockerVersion asks the Docker engine its version.
func RealDockerVersion(ctx context.Context) (string, error) {
	out, err := exec.CommandContext(ctx, "docker", "version", "--format", "{{.Server.Version}}").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// Prereqs is what lox init needs, and what it found.
type Prereqs struct {
	// Docker is the engine's version; "" when it does not answer.
	Docker string
	// DockerCLI: the docker command is installed (it may not answer).
	DockerCLI bool
	// Cosign and Lea are their paths, "" when not found.
	Cosign, Lea string
	// Launchers are each lock's launcher on PATH, "" when not found.
	Launchers map[string]string
}

// Ready reports whether lox init can go on: Docker answers and cosign
// (lox add and lox run verify every image) is installed.
func (p Prereqs) Ready() bool { return p.Docker != "" && p.Cosign != "" }

// CheckPrereqs looks for Docker, cosign, lea and the launchers.
func CheckPrereqs(ctx context.Context, e Env) Prereqs {
	p := Prereqs{Launchers: map[string]string{}}
	look := func(n string) string {
		if s, err := e.LookPath(n); err == nil {
			return s
		}
		return ""
	}
	p.DockerCLI = look("docker") != ""
	if p.DockerCLI {
		if v, err := e.DockerVersion(ctx); err == nil && v != "" {
			p.Docker = v
		}
	}
	p.Cosign = look("cosign")
	p.Lea = look("lea")
	for _, l := range Locks {
		p.Launchers[l] = look(l)
	}
	return p
}

// DockerHint is how to get Docker answering on goos.
func DockerHint(goos string, installed bool) string {
	if installed {
		if goos == "darwin" {
			return "start Docker Desktop (open -a Docker), then run lox init again"
		}
		return "start the Docker engine (sudo systemctl start docker), or check that your user may use it (docker info), then run lox init again"
	}
	if goos == "darwin" {
		return "install Docker Desktop: brew install --cask docker, then open -a Docker"
	}
	return "install Docker: curl -fsSL https://get.docker.com | sh (or your distribution's docker package), then sudo usermod -aG docker $USER and log in again"
}

// CosignHint is how to install cosign on goos.
func CosignHint(goos string) string {
	if goos == "darwin" {
		return "install cosign: brew install cosign"
	}
	return "install cosign: https://docs.sigstore.dev/cosign/system_config/installation/ (or your distribution's cosign package)"
}

// LeaHint is how to install lea.
const LeaHint = "install lea: curl -fsSL https://leadeck.dev/install.sh | sh"

// LauncherHint is how to install a lock's launcher.
func LauncherHint(lock string) string {
	return "install the " + lock + " launcher: https://github.com/DavidGodefroid/" + lock + "#install"
}
