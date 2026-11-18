package loxlive

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/DavidGodefroid/lockhub/internal/api"
	"github.com/DavidGodefroid/lockhub/internal/approve"
	"github.com/DavidGodefroid/lockhub/internal/hub"
	"github.com/DavidGodefroid/lockhub/internal/loxrun"
	"github.com/DavidGodefroid/lockhub/internal/peer"
	"github.com/DavidGodefroid/lockhub/internal/route"
)

// The status socket is what lox live shows another Unix user: a daemon
// that makes agents raise tickets and must know whether the locks serve
// and what became of a ticket, but must never decide one. That user is
// kept off the facade socket (whoever opens it can decide); here it gets,
// over HTTP/1.1 on a unix socket (0660, its group):
//
//	GET  /v1/health                          the Health
//	GET  /v1/tickets/{instance}/{id}         {"state": "pending|approved|denied|expired|withdrawn|consumed"}
//	POST /v1/tickets/{instance}/{id}/withdraw  204
//
// A withdrawal is taken only for a pending ticket whose requester's
// agent label, as its lock signed it and lox live verified it under the
// pinned lock key, starts with AgentPrefix: the tickets that daemon's
// own agents raised. It goes through the hub's withdrawal of a human's
// facade (audited, the lock told), under facade live. No route decides,
// reveals or renews a ticket.

// AgentPrefix starts the agent label of the tickets a client of the
// status socket may withdraw.
const AgentPrefix = "dutydesk:"

// StatusHub is what the status socket needs of the hub's facade socket
// (approve.Client).
type StatusHub interface {
	QueueAll(ctx context.Context, since uint64, wait time.Duration) (api.QueueResult, error)
	State(ctx context.Context, instance, id string) (api.TicketState, error)
	Withdraw(ctx context.Context, instance, id string, req api.WithdrawRequest) (api.WithdrawResult, error)
}

// Status serves the status socket.
type Status struct {
	Tracker *Tracker
	Hub     StatusHub
	// LockKeys reads the lock keys lox run pinned (again at each
	// withdrawal: a later lox run may pin others): a ticket's agent label
	// is read only from a ticket that verifies under its lock's.
	LockKeys func() map[string]ed25519.PublicKey
	// Log, if set, is told each withdrawal and refusal (one plain line).
	Log func(format string, args ...any)
}

// hubTimeout bounds a question to the hub on behalf of a client.
const hubTimeout = 5 * time.Second

// Server is the HTTP server of the status socket (Serve it on Listen's
// listener).
func (s *Status) Server() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/tickets/{instance}/{id}", s.ticket)
	mux.HandleFunc("POST /v1/tickets/{instance}/{id}/withdraw", s.withdraw)
	return &http.Server{Handler: mux, ConnContext: peer.ConnContext, ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
}

func (s *Status) logf(format string, args ...any) {
	if s.Log != nil {
		s.Log(format, args...)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

// CurrentHealth is the tracker's health with the hub's pending tickets
// counted now; a hub that does not answer is not serving.
func (s *Status) CurrentHealth(ctx context.Context) Health {
	h := s.Tracker.Health()
	ctx, cancel := context.WithTimeout(ctx, hubTimeout)
	defer cancel()
	q, err := s.Hub.QueueAll(ctx, 0, 0)
	if err != nil {
		if h.Serving {
			h.Detail = DetailHubDown
		}
		h.Serving = false
		return h
	}
	h.Pending = len(q.Tickets)
	return h
}

func (s *Status) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.CurrentHealth(r.Context()))
}

// stateOf is a hub ticket state in the status socket's six: a ticket
// whose lock was removed ended without a decision, as one withdrawn.
func stateOf(hubState string) string {
	switch hubState {
	case "pending", "approved", "denied", "expired", "withdrawn", "consumed":
		return hubState
	case "lock_removed":
		return "withdrawn"
	}
	return ""
}

// lookup asks the hub for a ticket's state: 404 when it knows none, 503
// when it does not answer.
func (s *Status) lookup(w http.ResponseWriter, r *http.Request) (string, bool) {
	// Only what a lock instance and a ticket id look like goes to the
	// hub: nothing a path could smuggle (a slash, a dot-dot, a query).
	if !validName(r.PathValue("instance")) || !validName(r.PathValue("id")) {
		writeErr(w, http.StatusNotFound, "no such ticket")
		return "", false
	}
	ctx, cancel := context.WithTimeout(r.Context(), hubTimeout)
	defer cancel()
	st, err := s.Hub.State(ctx, r.PathValue("instance"), r.PathValue("id"))
	var he *approve.HubError
	switch {
	case errors.As(err, &he) && (he.Status == http.StatusNotFound || he.Status == http.StatusBadRequest):
		writeErr(w, http.StatusNotFound, "no such ticket")
		return "", false
	case err != nil:
		writeErr(w, http.StatusServiceUnavailable, "the hub does not answer")
		return "", false
	}
	state := stateOf(st.State)
	if state == "" {
		writeErr(w, http.StatusServiceUnavailable, "the hub gave a state lox live does not know")
		return "", false
	}
	return state, true
}

func (s *Status) ticket(w http.ResponseWriter, r *http.Request) {
	if state, ok := s.lookup(w, r); ok {
		writeJSON(w, http.StatusOK, map[string]string{"state": state})
	}
}

func (s *Status) withdraw(w http.ResponseWriter, r *http.Request) {
	instance, id := r.PathValue("instance"), r.PathValue("id")
	p := peer.From(r.Context())
	if !p.Known {
		writeErr(w, http.StatusForbidden, "the status socket cannot identify this connection's user")
		return
	}
	state, ok := s.lookup(w, r)
	if !ok {
		return
	}
	refuse := func(why string) {
		s.logf("lox live: status socket: withdrawal of %s/%s by uid %d refused: %s", instance, id, p.UID, why)
		writeErr(w, http.StatusForbidden, why)
	}
	if state != "pending" {
		refuse("the ticket is " + state + ", not pending")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), hubTimeout)
	defer cancel()
	q, err := s.Hub.QueueAll(ctx, 0, 0)
	if err != nil {
		writeErr(w, http.StatusServiceUnavailable, "the hub does not answer")
		return
	}
	var items []api.QueueItem
	for _, it := range q.Tickets {
		if it.Instance == instance && it.ID == id {
			items = append(items, it)
		}
	}
	if len(items) != 1 {
		refuse("the ticket is not pending any more")
		return
	}
	// The agent label, from the ticket its lock signed, checked under the
	// pinned lock key: never from an unverified one.
	var pinnedKeys map[string]ed25519.PublicKey
	if s.LockKeys != nil {
		pinnedKeys = s.LockKeys()
	}
	if _, pinned := pinnedKeys[instance]; !pinned {
		refuse("no pinned key for its lock: its requester cannot be checked")
		return
	}
	t := loxrun.Pending(items, pinnedKeys)[0]
	if t.Unverifiable || !strings.HasPrefix(t.Agent, AgentPrefix) {
		refuse("only a ticket raised by a " + AgentPrefix + " agent is withdrawn here")
		return
	}
	res, err := s.Hub.Withdraw(ctx, instance, id, api.WithdrawRequest{Facade: route.Live,
		Display: fmt.Sprintf("uid %d (status socket)", p.UID), Via: hub.ViaLive})
	if err != nil {
		var he *approve.HubError
		if errors.As(err, &he) {
			// Why goes to the journal, not to the socket's reader.
			s.logf("lox live: status socket: the hub refused the withdrawal of %s/%s: %s", instance, id, he.Message)
			refuse("the hub refused the withdrawal")
			return
		}
		writeErr(w, http.StatusServiceUnavailable, "the hub does not answer")
		return
	}
	s.logf("lox live: status socket: %s/%s of agent %s withdrawn for uid %d (%s)", instance, id, t.Agent, p.UID, res.Reason)
	w.WriteHeader(http.StatusNoContent)
}

// validName reports a lock instance or a ticket id as the hub names
// them: 1 to 128 of [A-Za-z0-9._-], and not a dot name.
func validName(s string) bool {
	if s == "" || len(s) > 128 || s == "." || s == ".." {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// Listen opens the status socket at path, mode 0660, of group (a name or
// a gid; "": the user's own group). Its directory is made 0700 when
// missing; it must be a real directory of this user's that group and
// others cannot write: anywhere else another account could swap the
// socket for one of its own, or for a link. A socket nobody answers on (a
// lox live that died) is replaced; anything else at path is refused. The
// socket is created with its mode (the umask) and given its group
// without following a link (lchown): no chmod of a path.
func Listen(path, group string) (net.Listener, error) {
	gid := -1
	if group != "" {
		if n, err := strconv.Atoi(group); err == nil && n >= 0 {
			gid = n
		} else {
			g, err := user.LookupGroup(group)
			if err != nil {
				return nil, fmt.Errorf("--status-group %s: %w", group, err)
			}
			if gid, err = strconv.Atoi(g.Gid); err != nil {
				return nil, fmt.Errorf("--status-group %s: gid %q", group, g.Gid)
			}
		}
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	di, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	st, ok := di.Sys().(*syscall.Stat_t)
	if !di.IsDir() || !ok || int(st.Uid) != os.Geteuid() || di.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s (the status socket's directory) must be a directory of yours that group and others cannot write (mode %v): another account could replace the socket there", dir, di.Mode())
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket: remove it, or pick another --status-socket", path)
		}
		if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
			c.Close()
			return nil, fmt.Errorf("%s: another lox live answers on it", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Created 0600: until its group is set, only lox live's user can connect
	// (0660 at once would open it to that user's primary group meanwhile).
	old := syscall.Umask(0o177)
	ln, err := net.Listen("unix", path)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	// Group and mode are set relative to the checked directory's descriptor,
	// never by path: a parent swapped for a link cannot redirect them, and
	// only the directory's owner (lox live) can replace the entry itself.
	if err := setSocketAccess(dir, filepath.Base(path), gid); err != nil {
		ln.Close()
		if gid >= 0 {
			return nil, fmt.Errorf("--status-group %s: %w (lox live's user must be a member of the group)", group, err)
		}
		return nil, err
	}
	return ln, nil
}

// setSocketAccess gives the socket name in dir its group (gid >= 0) and the
// mode 0660, through a descriptor of dir opened without following a link.
func setSocketAccess(dir, name string, gid int) error {
	dfd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	defer unix.Close(dfd)
	var ds unix.Stat_t
	if err := unix.Fstat(dfd, &ds); err != nil {
		return err
	}
	if int(ds.Uid) != os.Geteuid() || ds.Mode&0o022 != 0 {
		return fmt.Errorf("%s changed under lox live: not a directory of yours closed to group and others", dir)
	}
	var st unix.Stat_t
	if err := unix.Fstatat(dfd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s/%s is not the socket lox live made", dir, name)
	}
	if gid >= 0 {
		if err := unix.Fchownat(dfd, name, -1, gid, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
	}
	// The entry was just checked to be our socket, not a link.
	return unix.Fchmodat(dfd, name, 0o660, 0)
}
