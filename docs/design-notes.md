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
outside the log: `lock audit verify --lock INSTANCE=PATH --anchors FILE`
keeps each lock log's last chained line and its hash (`Summary.Anchor()`) in
a host-only file (0600). On the next run it checks the log with
`audit.VerifyAnchored`. That refuses a log that ends before its anchor,
whose anchored line was stripped of its chain, or whose anchored line hashes
differently. `lock audit verify --lock` also checks every record of a hub
decision in the lock's log against the decision the hub signed for that
instance and ticket (outcome, approver, facade, and `hub_sig` when the
record has it). The hub's own log is signed record by record.

**Residual.** A cut made after the last anchor is seen only at the next
run. A lock log that was never verified with `--anchors` has no anchor:
there, only the chain and the hub-decision cross-check apply. Run `lock
audit verify --lock … --anchors …` on a schedule to narrow that window.

## Compatibility matrix: built on the pinned lockkit only

**Plan.** The CI compat check was to be the matrix {pinned lockkit,
lockkit N-1} × the signed ticket fixtures of `lockkit/ticket/testdata`.

**Code.** The `compat` job of `.github/workflows/ci.yml` builds lockhub only
on the pinned lockkit (go.mod: v0.6.0). It checks the codec against the
fixtures of three lockkit releases: the pinned one, the release before it
(v0.5.0), and the newest one (v0.7.1 today). Together these stand for the
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
