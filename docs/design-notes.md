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
outside the log: `lox audit verify --data DIR --hub-key-file FILE --lock
INSTANCE=PATH --anchors FILE` keeps, for each lock log that verifies, the
number of its last chained line and that line's hash (`Summary.Anchor()`)
in a host-only file (0600). The anchor only moves forward on a log that
verifies. On the next run it checks the log with
`audit.VerifyAnchored`. That refuses a log that ends before its anchor,
whose anchored line was stripped of its chain, or whose anchored line hashes
differently. `lox audit verify --lock` also checks every record of a hub
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
apply. Running `lox audit verify … --lock … --anchors …` often narrows
the unanchored window.

## Compatibility matrix: built on the pinned lockkit only

**Plan.** The CI compat check was to be the matrix {pinned lockkit,
lockkit N-1} × the signed ticket fixtures of `lockkit/ticket/testdata`.

**Code.** The `compat` job of `.github/workflows/ci.yml` is the plan's full
grid: lockhub built on the pinned lockkit (go.mod: v0.8.1) and on the
release before it (v0.8.0), its codec checked against the fixtures of three
lockkit releases: the pinned one, the release before it, and the newest one
(v0.8.1 as of 2026-10-31). Together these stand for the tickets of locks
built on an older, the same, or a newer lockkit (`scripts/compat.sh
pinned|prev pinned|prev|latest`).

From lockhub v0.2.0 to v0.2.6 (pinned on lockkit v0.6.0) the job built on
the pinned lockkit only: lockhub used lockkit v0.6.0 APIs that v0.5.0 did
not have (`ticket.ChangeUnchecked`, for a renewal's unchecked inputs in
`internal/approve`), so a build on N-1 could only fail. If a later pin's
previous release lacks an API lockhub uses again, `build: [pinned]` and a
note here say so; `sh scripts/compat.sh prev pinned` (on a copy: the script
rewrites go.mod and go.sum) tries it by hand.
