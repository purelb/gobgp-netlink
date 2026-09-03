# Locking contract after the v4.9.0 merge

Written before `pkg/server/server.go` was resolved, because that resolution is
the one change in the catch-up that can compile, pass CI and still be wrong. The
symptom would be a wrong kernel FIB on a production node under peer churn, in
fork-only code no upstream reviewer has read.

## What changed

`sharedData` was a single exclusive mutex. Upstream split it in two:

```go
// before (fork, = merge base)          // after (v4.9.0)
type sharedData struct {                type sharedData struct {
    mu sync.Mutex                           mu               sync.RWMutex
}                                           propagateBuckets [propagateBucketCount]sync.Mutex
                                        }
```

`handleFSMMessage` used to take `mu.Lock()`, so **every peer's message
processing was globally serialised**. It now takes `mu.RLock()` and escalates to
`Lock()` only around `stopNeighbor`. Peers therefore process concurrently, and
the per-destination work that used to be covered by the global exclusive lock is
now covered by `propagateBuckets[hash(destLocalKey)]`, taken inside
`propagateUpdate` around the per-path closure.

## The contract, stated

1. **`shared.mu.Lock()` still excludes everything.** A writer excludes every
   `RLock()` holder, so any code that previously relied on holding `mu` for
   mutual exclusion against the FSM path still has it — *provided it takes the
   write lock*.
2. **`RLock()` holders may now run concurrently with each other.** Anything
   reached only from `handleFSMMessage` must be safe against itself.
3. **A bucket lock protects one destination, not the RIB.** Two paths with
   different `destLocalKey` are processed in parallel. Code that assumed
   "propagateUpdate is serialised" is wrong; code that assumed "this
   destination is serialised" is right.
4. **No netlink syscall runs under `shared.mu`, in either direction.** This
   predates the merge and is unchanged. It is what keeps a blocking kernel call
   off the BGP hot path.

## Where the fork sits in it

The netlink import loop takes the **write** lock (`shared.mu.Lock()`), so it is
still exclusive against everything, including the now-concurrent FSM readers.
Its three-phase structure — locked snapshot, unlocked scan, locked publish — is
unaffected. `znetlink.go` records this in 15 places; those comments remain
accurate, but "the one goroutine that acquires shared.mu" is now "the one
goroutine that acquires it exclusively".

The netlink **export** hook is the part that moves. It sits inside
`propagateUpdate`, and in upstream's structure that means it runs inside the
per-path closure that holds `propagateBucket(path)`. So:

- it is serialised **per destination**, not globally;
- two different prefixes can be exported concurrently;
- the export client's own locks (`e.mu`, `dampenMu`, `statsMu` — 78 uses in
  `netlink_export.go`) are what make that safe, and they are why this is
  expected to hold.

## What this does not prove

`go test -race` will catch a corrupted map. It will **not** catch the export hook
interleaving differently with `netlink_export.go`'s dampening flush, because that
fires from a `time.AfterFunc` goroutine that was always outside the lock. That
interaction is the residual risk of this merge, and the reason the hardware gate
matters more here than anywhere else in the plan.

There is now exactly **one** flush timer for the whole client, not one per
prefix. `flushDampened` drains at most `dampenFlushBudget` due prefixes per pass,
issues their netlink writes **outside** `dampenMu`, then re-arms under it. Two
consequences for this contract:

- The window in which a prefix can be re-scheduled while its own write is in
  flight is now the whole budgeted pass, not a single prefix's write. That is
  safe because the flush deletes an entry from `pendingUpdates` before releasing
  the lock, so a concurrent `scheduleUpdate` creates a fresh entry rather than
  mutating one being written.
- `scheduleUpdate` runs under `dampenMu` on the export hook's path, so anything
  it does that scales with the number of pending prefixes serialises the hook.
  It must stay O(1); `armFlushAtLocked` exists for that reason, and
  `BenchmarkScheduleBurst*` is what detects a regression.

## Acceptance

- `go test -race ./pkg/server/... -count=5` with at least two concurrent peers.
- Upstream's own `91337e95` race tests for the table manager.
- Hardware: two live FRR neighbours, route churn, and `netlink export stats`
  reporting zero errors afterwards.
