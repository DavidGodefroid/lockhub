package hub

import (
	"context"

	"github.com/DavidGodefroid/lockhub/internal/audit"
	"github.com/DavidGodefroid/lockhub/internal/state"
	"github.com/DavidGodefroid/lockhub/internal/store"
)

// SweepOne is what Sweep does to one ticket it listed as due: a test
// runs it after a Decide got in between (the sweeper's race).
func (h *Hub) SweepOne(ctx context.Context, ref store.Ref) error {
	return h.change(ctx, ref, state.Expire, audit.Record{})
}

// GiveStart is the give sequence a poll beginning now records.
func (h *Hub) GiveStart() uint64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.giveSeq
}

// OpenRequestsFor is openRequests of a poll that began at start.
func (h *Hub) OpenRequestsFor(instance string, start uint64) ([][]byte, bool) {
	reqs, fresh, _ := h.openRequests(instance, start)
	return reqs, fresh
}

// OpenCount is how many requests are open for instance.
func (h *Hub) OpenCount(instance string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.reqs[instance])
}
