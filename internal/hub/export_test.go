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
