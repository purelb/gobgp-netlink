# Plan measurements

The v4.9.0 merge plan required four measurements and said to record them. They
were not taken at the time, so the merge's headline benefit was unquantified and
the BFD timing floor rested on arithmetic rather than observation. This is that
record.

Taken 2026-09-03. Benchmarks on an Intel i9-14900F (32 threads); the wire and
cgroup measurements on 192.168.151.193 against FRR 10.4.1 neighbours.

## §6.6 Destination shard count — keep 2048

The plan took upstream's `destinationShardCount = 2048` but required measuring
before accepting it, and would only diverge to 64 on evidence. The concern was
per-poll garbage: k8gobgp polls the RIB, so sharding overhead multiplies.

`go test -bench BenchmarkTable -benchmem -benchtime 200x`:

| Benchmark | 2048 shards | 64 shards |
| --- | --- | --- |
| `TableInsert/IPv4/1K` | 639,273 B/op · 14,149 allocs | 292,361 B/op · 7,581 allocs |
| `TableInsert/IPv4/10K` | 2,308,689 B/op · 78,197 allocs | 2,731,043 B/op · 70,965 allocs |
| `TableInsert/IPv4/100K` | 36,129,043 B/op | 37,134,341 B/op |
| `TableGetDestinations/IPv4/1K` | 97,552 B/op · 3,012 allocs | 97,552 B/op · 3,012 allocs |
| `TableGetDestinations/IPv4/100K` | 8,019,092 B/op | 8,019,096 B/op |

**Decision: keep 2048.** Two findings, both against diverging.

The poll path does not care. `GetDestinations` is byte-identical at both shard
counts, at every table size. The premise that sharding inflates per-poll garbage
is not supported: the cost is in table *construction*, not traversal.

Where 2048 does cost more it is small and only at small tables — about 347 KB
extra per 1K-route insert, which is 0.13% of a 256 Mi limit. At 10K and above
2048 is actually the cheaper of the two on bytes. Diverging from upstream to
save 347 KB at the one table size where it helps is not a trade worth carrying
in a fork whose purpose is reducing divergence.

## §6.7 UPDATE packing — 300 prefixes in 2 UPDATEs

The plan calls this "the number that justifies the merge". The fork previously
emitted one UPDATE per IPv6 prefix; upstream packs many NLRIs into one MP_REACH,
bucketed by nexthop.

300 IPv6 /128 host routes sharing one nexthop — the PureLB VIP shape — measured
as the delta in `messages.sent.update` across a full session reset, so the peer
re-learns the whole table in one burst:

| Reset | UPDATEs before | after | delta |
| --- | ---: | ---: | ---: |
| 1 | 303 | 305 | **2** |
| 2 | 305 | 307 | **2** |

**300 routes advertised in 2 UPDATEs**, reproducible across two independent
resets, exactly as predicted. That is a 150× reduction against the fork's
previous behaviour.

A first attempt measured 300 UPDATEs and was wrong: it added the routes with 300
separate `gobgp global rib add` calls, so each was its own advertisement. The
packing applies to a bulk advertisement, which is what a session reset produces
and what a peer coming up actually does.

## §11 CFS throttling — the stall is real

§7.2's timing floor rests on the claim that under `limits.cpu: 500m` the CFS
quota is exhausted partway through each period, leaving the process frozen for
the remainder. That was arithmetic. Measured with a saturating load in a
`CPUQuota=50%` scope, which is the same `cpu.max 50000 100000` a 500m limit
produces:

| t | `nr_periods` | `nr_throttled` | `throttled_usec` |
| ---: | ---: | ---: | ---: |
| 6 s | 60 | 59 | 2,946,893 |
| 18 s | 180 | 179 | 8,940,245 |

Over the 120 periods between the two samples, **120 were throttled** and
5,993,352 µs were spent stalled — **≈49.9 ms of every 100 ms period**.

That is a single-threaded load, which exhausts a 50 ms quota in 50 ms of wall
clock and so stalls for the remaining ~50 ms. The plan's ~75 ms figure assumes
`GOMAXPROCS=2` burning the same quota in ~25 ms; the mechanism is confirmed and
the worst case scales with parallelism, so ~75 ms at two threads is consistent
with this data.

Against the profiles in §7.2:

| Profile | Detection | 75 ms stall as % |
| --- | ---: | ---: |
| 1000 ms × 3 | 3000 ms | 2.5% |
| 300 ms × 3 | 900 ms | 8% |
| 100 ms × 3 | 300 ms | 25% |
| 50 ms × 3 | 150 ms | 50% |

**The 300 ms × 3 floor enforced by `BfdConfig.Validate` is justified by
measurement**, not only by arithmetic. Note the caveat: this is a *saturating*
load. Steady-state gobgpd does not saturate its quota, but a route-churn burst
can, which is precisely the correlated failure §7.4's dampening bound addresses.

## Steady state

For reference, the deployed configuration on the test box during these runs:
2 peers, 45 and 46 routes received, netlink export 0 errors throughout, BFD
detection measured at 838 ms / 650 ms / 652 ms / 881 ms across four separate
timer-expiry tests at the 300 ms × 3 profile.

## Reproducing

```bash
# §6.6
go test ./internal/pkg/table/ -run XXX -bench BenchmarkTable -benchmem -benchtime 200x

# §6.7 — with N routes in the RIB, delta of messages.sent.update across
# `gobgp neighbor <peer> reset`

# §11
systemd-run --scope -p CPUQuota=50% -p CPUAccounting=yes <load> &
grep -E 'nr_periods|nr_throttled|throttled_usec' \
  /sys/fs/cgroup/system.slice/<unit>.scope/cpu.stat
```
