# Design notes: accepted deviations

The hub's design plan is not published. This page records where the
released code deliberately departs from it, so a reader of the code (or of
the plan) does not take the difference for a bug.

## Lock-side audit: an unsigned genesis, protected by anchors

**Plan.** A lock's audit log was to start its hash chain at a signed
"genesis" record.

**Code.** lockkit's audit chain (`audit/chain.go`) starts at the constant
`audit.Genesis` (the string `"genesis"`): the first record's `prev_hash`.
It is not a signed record. Each later record's `prev_hash` is the SHA-256
of the line before it, so a record that is edited, removed, inserted or
reordered breaks the chain (`audit.Verify`).

The chain alone cannot see two things: records cut from the end, and a log
stripped of every `prev_hash` (which reads as a legacy log). A signed
genesis would not catch either one. What catches them is an anchor kept
outside the log: `lock audit verify --data DIR --hub-key-file FILE --lock
INSTANCE=PATH --anchors FILE` keeps, for each lock log that verifies, the
number of its last chained line and that line's hash (`Summary.Anchor()`)
in a host-only file (0600). The anchor only moves forward on a log that
verifies. On the next run it checks the log with
`audit.VerifyAnchored`. That refuses a log that ends before its anchor,
whose anchored line was stripped of its chain, or whose anchored line hashes
differently. `lock audit verify --lock` also checks every record of a hub
decision in the lock's log against the decision the hub signed for that
instance and ticket (outcome, approver, facade, and `hub_sig` when the
record has it). The hub's own log is signed record by record.

**Residual.** A cut into records an anchor already covers is caught at the
next run. Records written since the last anchored run are not covered: cut
back to the anchor or anywhere after it, the log still verifies, and the
anchor moves to the shortened end. The one trace left is the hub-decision
cross-check: a cut record of a hub decision shows in its count of hub
decisions the log has no record of, which is reported, not failed (a lock
may not have acted on a decision yet). A lock log never verified with
`--anchors` has no anchor at all: only the chain and the cross-check
apply. Running `lock audit verify … --lock … --anchors …` often narrows
the unanchored window.

## Compatibility matrix: built on the pinned lockkit only

**Plan.** The CI compat check was to be the matrix {pinned lockkit,
lockkit N-1} × the signed ticket fixtures of `lockkit/ticket/testdata`.

**Code.** The `compat` job of `.github/workflows/ci.yml` builds lockhub only
on the pinned lockkit (go.mod: v0.6.0). It checks the codec against the
fixtures of three lockkit releases: the pinned one, the release before it
(v0.5.0), and the newest one (v0.7.1 as of 2026-10-30). Together these stand for the
tickets of locks built on an older, the same, or a newer lockkit
(`scripts/compat.sh pinned pinned|prev|latest`).

lockhub is not built on N-1, because it uses lockkit v0.6.0 APIs that
v0.5.0 does not have: for instance `ticket.ChangeUnchecked`, for a renewal's
unchecked inputs (`internal/approve`). A lockhub built on N-1 does not
compile, so that cell could only fail. To try it by hand, run
`sh scripts/compat.sh prev pinned` (or `prev latest`) on a copy: the script
rewrites go.mod and go.sum. The fixture side of the matrix, which is what
the locks in the field send, is still covered for pinned, previous and
latest.

When a later lockhub pins a lockkit whose previous release has every API it
uses, `build: [pinned, prev]` in the matrix restores the plan's full grid.
