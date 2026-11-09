package family

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/DavidGodefroid/lockhub/internal/approve"
)

// Two workspaces on one host share the facade socket
// ($XDG_RUNTIME_DIR/lockhub/facade.sock): the first workspace's hub
// serves it, the second's cannot (another hub is serving it). Before lox
// run serves decisions, it asks the hub on the socket for its key and
// compares it with its own workspace's (hub.pub in the state directory),
// so that it never shows, nor decides, another workspace's tickets
// (#172).

// ErrFacadeUnserved is CheckFacadeHub's answer when no hub answers on the
// socket (none yet, or it stopped).
var ErrFacadeUnserved = errors.New("no hub answers on the facade socket")

// ErrFacadeOldHub is CheckFacadeHub's answer when the hub on the socket
// predates GET /v1/hub: it cannot say whose it is.
var ErrFacadeOldHub = errors.New("the hub on the facade socket predates GET /v1/hub")

// ForeignFacadeError is CheckFacadeHub's answer when another hub than
// this workspace's serves the socket.
type ForeignFacadeError struct {
	Socket string
	// Key is the serving hub's key; Workspace and Project are its
	// workspace's, when a state directory of this host holds that key
	// ("" otherwise).
	Key, Workspace, Project string
}

func (e *ForeignFacadeError) Error() string {
	who := fmt.Sprintf("another hub (key %s), not this workspace's", e.Key)
	if e.Workspace != "" {
		who = fmt.Sprintf("the hub of workspace %s (%s)", e.Workspace, e.Project)
	}
	return fmt.Sprintf("the facade socket %s is served by %s; stop it, or run this workspace with its own XDG_RUNTIME_DIR", e.Socket, who)
}

// HubKeyAsker asks the hub on the facade socket for its key
// (approve.Client).
type HubKeyAsker interface {
	HubKey(ctx context.Context) (string, error)
}

// CheckFacadeHub says whether the hub on the facade socket sock (asked
// through c) is the one of the workspace whose state directory is state:
// nil when it is; ErrFacadeUnserved (wrapping the dial's error) when none
// answers; ErrFacadeOldHub when it cannot tell; a *ForeignFacadeError
// when it is another's. A workspace without a hub key yet owns no hub, so
// any hub that answers is another's. The other workspaces' state
// directories, next to state, name the serving hub's workspace.
func CheckFacadeHub(ctx context.Context, c HubKeyAsker, sock, state string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	key, err := c.HubKey(ctx)
	if err != nil {
		var he *approve.HubError
		if errors.As(err, &he) {
			if he.Status == http.StatusNotFound {
				return ErrFacadeOldHub
			}
			return err
		}
		return fmt.Errorf("%w: %v", ErrFacadeUnserved, err)
	}
	key = strings.TrimSpace(key)
	own, _ := os.ReadFile(filepath.Join(state, "hub.pub"))
	if key != "" && key == strings.TrimSpace(string(own)) {
		return nil
	}
	e := &ForeignFacadeError{Socket: sock, Key: key}
	e.Workspace, e.Project = hubOwner(filepath.Dir(state), key)
	return e
}

// hubOwner finds the workspace whose last lox run applied hub key key,
// among the state directories under root ($XDG_STATE_HOME/lockfamily).
func hubOwner(root, key string) (workspace, project string) {
	ents, _ := os.ReadDir(root)
	for _, d := range ents {
		if !d.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(root, d.Name(), UpFile))
		if err != nil {
			continue
		}
		var s UpState
		if json.Unmarshal(b, &s) == nil && key != "" && s.HubKey == key {
			return s.Workspace, s.Project
		}
	}
	return "", ""
}
