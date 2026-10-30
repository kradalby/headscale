# Server stress tests

`TestScale` exercises a real Headscale server, SQLite, policy compilation,
the world and its map sessions, Noise, and Tailscale control clients over the
existing in-memory network. Every registered node has a live control client.
The test cases and their policies are together in `scale_test.go`.

The ordinary test suite runs all five policies with 12 nodes. Larger runs
require `HEADSCALE_STRESS_NODES`; setting it replaces the small node count.
Nothing large is enabled by `go test ./...` or by omitting `-short`.

| Case               | Expected visibility                                          | Main pressure                                      |
| ------------------ | ------------------------------------------------------------ | -------------------------------------------------- |
| `allow_all`        | Everyone sees everyone                                       | Dense graph, map size, broadcast fan-out           |
| `isolated`         | No peers                                                     | Registration and state updates without peer output |
| `personal_devices` | Up to ten devices belonging to the same user                 | Per-node policy compilation and isolation          |
| `shared_service`   | One tagged service sees everyone; everyone else sees only it | Uneven fan-out and tag identity                    |
| `personal_ssh`     | Personal devices, with SSH to the same user's devices        | Per-node SSH policy generation                     |

Each case enrolls its clients, sends three Hostinfo bursts, revokes access,
restores access, and reconnects one client per user. Bursts change one node
per ten-node user; the final user can have fewer nodes. Registration uses
batches of at most 32 concurrent logins. Map sessions coalesce changes for
the harness's 50 ms batch delay. Explicit scale runs do not hold writes
during an HA outage; the routine 12-node smoke run holds them for 10 ms.

Completion means the intended state reached every affected client, with the
exact permitted peer IDs, fresh OS markers, and online peers. Bounded
IPv4/IPv6 filter probes check allowed TCP traffic and denied ports, protocols,
and cross-user access. SSH checks the accept action, root mapping, and exact
same-user principal addresses. After reconnecting, a new policy generation
broadcast checks delivery on every recovered stream, including isolated nodes.
Policy changes carry a new node attribute so an old map cannot satisfy a
policy wait. Revocation also checks that packet filter rules are empty.
Each phase checks both client streams and server connections. Convergence
has a shared two-minute deadline per wait, and existing login helpers retain
their ten-second registration timeout.
There are no sleep-based completion checks or automatic reconnect retries.

## Run

Use the pinned Go toolchain from `nix develop`, as for the other server tests.

```sh
# Fast coverage of every case; this also runs in the ordinary suite.
go test ./hscontrol/servertest -run '^TestScale$' -count=1 -v

# Select a scale and one policy. All nodes are real connected control clients.
HEADSCALE_STRESS_NODES=500 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/500_nodes/personal_devices$' \
  -count=1 -v -timeout=20m

HEADSCALE_STRESS_NODES=1000 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/1000_nodes/shared_service$' \
  -count=1 -v -timeout=30m

HEADSCALE_STRESS_NODES=10000 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/10000_nodes/personal_devices$' \
  -count=1 -v -timeout=60m

# A compute-constrained run: one Go execution thread.
HEADSCALE_STRESS_NODES=500 GOMAXPROCS=1 GOMEMLIMIT=512MiB \
  go test ./hscontrol/servertest -run '^TestScale/500_nodes/personal_devices$' \
  -count=1 -v -timeout=30m
```

Omit the final policy component of `-run` to run every policy at that size.
Choose large dense runs deliberately: 10,000 all-to-all clients hold
99,990,000 directed peer entries before accounting for serialized maps and
other state. A sparse output graph still requires policy/peer calculations;
it does not guarantee linear CPU use. `GOMEMLIMIT` is a soft Go heap target,
not an RSS cap. Go's resource settings constrain server and clients together.

## Read results and find congestion

Each phase logs wall time, allocated bytes during the phase, ending heap
bytes, GC cycles, goroutines, registered nodes, live clients, and visible
peer entries. Ending heap is not peak memory or RSS. These numbers cover
the whole test process, including clients and assertions. They are useful
for comparing identical workloads and finding limits, not server-only
latency or memory claims. Old client netmap histories are disabled; the
current maps remain, as they do in connected clients.

Repeat one selected workload with fixed toolchain, node count, runtime
settings, and hardware. Disable Go's test cache with `-count=1`, run each
sample in a fresh process, keep unrelated heavy jobs off the host,
and save the commit ID, `go version`, CPU model, and command with the log.
Keep enrollment and steady-state phase results separate. Failures and
timeouts are results, not samples to silently retry or discard.

```sh
mkdir -p control_logs/server-scale
HEADSCALE_STRESS_NODES=500 GOMAXPROCS=4 \
  go test ./hscontrol/servertest -run '^TestScale/500_nodes/personal_devices$' \
  -count=1 -v -timeout=20m \
  -cpuprofile=control_logs/server-scale/cpu.prof \
  -memprofile=control_logs/server-scale/heap.prof \
  >control_logs/server-scale/run.log 2>&1
go tool pprof control_logs/server-scale/cpu.prof
```

Use `-trace=control_logs/server-scale/trace.out` in a separate diagnostic run
to inspect scheduling, blocking, and GC. Profiles include setup, teardown,
test clients, and assertions. In the pinned Tailscale dependency, zstd also
performs extra runtime stack inspection in test binaries; confirm CPU
findings against a standalone server before optimizing them. Docker/real
tailscaled tests remain necessary for network behavior, data-plane traffic,
and a server-only resource ceiling.

## Policy and map microbenchmarks

The mapper's `BenchmarkScalingWrites` uses ten users or twenty tags regardless
of node count. That measures growth within a fixed policy, not growth in
policy diversity. It selects a node from the existing streams before each
write. Endpoint writes use `UpdateNodeFromMapRequest`, including SQLite
persistence, without `ListNodes` or the test insertion helper's
whole-tailnet name scan. Rejoin still measures test-helper deletion and
insertion, including name validation, not authentication or durable
registration. The encoder uses the same cached node JSON and zstd
compression as the poll loop.

`ignored-health` measures alternating unchanged and rejected health requests
on offline nodes without approved routes. It does not measure accepted
hidden-state mutations. Earlier results named this workload `hidden`; those
results must not be interpreted as evidence about actual health transitions.

`policy/<shape>` names the starting policy. Setup replaces that policy with
`*` to `*:2` and delivers the expansion, so the timed loop only alternates ports
1 and 2 under full visibility: a steady recompile and diff, not the one-time
visibility expansion the replacement causes — every iteration is a change. Under the old arrangement, that expansion
dominated the first write — `policy/self` at 10,000 nodes expanded ten
1,000-node user groups from 999 to 9,999 peers per client, 90,000,000 added
peer entries across 10,000 updated sessions, a cost that belongs to setup.

The `peer-renders/op` metric sums `len(netMap.changed)` across sessions:
added or pointer-changed peer references, excluding removals. It does not
count shared `peerRenders.render` calls or `TailNode` cache misses, and
pointer changes need not produce wire changes. Successful setup maps,
updates and reconnects call `Delivered` after encoding (or after setup's
simulated delivery); untimed checks reject retained failed-write attempts.

`BenchmarkPeerClassesDiversity` in `hscontrol/policy/v2` grows identities and
rules with the tailnet:

- `pairs`: N nodes, N/2 independent IP grants, N classes, one peer per node.
- `tag-pairs`: the same visibility with N distinct tags and N/2 tag grants.
- `dense`: N/2 distinct sources can reach everyone, producing N/2+1 classes
  and dense output.
- `self`: N/2 users with two devices each and an `autogroup:self` grant.
- `allow-all`: one shared class, the fixed-diversity comparison.

Each shape separates policy compilation, class construction without previous
sides (`fresh`), and construction reusing unchanged nodes and rules
(`reuse`). These are individual stages, not registration latency. In
particular, `reuse` does not include a policy edit or a joining node.
Construction phases report `classes/op`: the class views the phase's own
build produced, including a shared base view that per-node rules may
supersede. Compilation does not build or report class views.

Run from the Nix shell:

```sh
go test ./hscontrol/policy/v2 -run '^$' -bench '^BenchmarkPeerClassesDiversity$' -benchtime=200ms -count=5 -cpu=1
go test ./hscontrol/mapper -run '^$' -bench '^BenchmarkFirstMap/nodes=1000$/' -benchtime=200ms -count=5 -cpu=1
go test ./hscontrol/mapper -run '^$' -bench '^BenchmarkFirstMap/nodes=10000$/' -benchtime=200ms -count=5 -cpu=1
```

Class construction used to compare every class pair, intersecting up to
ceil(M/64) matcher words for M rules. Sparse sides now join the classes on
opposite sides of each matcher, deduplicating symmetric neighbors; the
build records which path ran, and the diversity suite asserts the sparse
shapes join while the dense shape keeps the scan. Dense sides or excessive
repeated joins retain the short-circuit pair scan. The join changes only
the shared-rule calculation; per-node self/via grants still add their peers
afterwards. An unchanged visibility relation includes self edges inside a
class; `Peers` removes the requesting node.

This does not make the entire build linear. Fresh side evaluation still
checks N nodes against M matchers. Reuse remaps matcher bits per node, also
O(NM). Stored side bitsets cost O(N ceil(M/64)); views can cost O(NC) for C
classes, reaching O(N²). Policy diversity and dense output remain
architectural limits: measurements of this join live in the pull request
that introduced it, and new hardware deserves new measurements, not these.

`BenchmarkFirstMap` distinguishes `warm-hub`, `cold-hub`, and `new-state`
for both JSON and zstd. A cold hub starts new render/class/encoding caches
but uses an already compiled world. `new-state` also reopens the existing
SQLite database, loads nodes, compiles policy and constructs peers; state
closure is included in its time. Neither case restarts the OS process,
performs HTTP/Noise handshakes, or measures a concurrent reconnect storm.
zstd in test binaries has the extra stack inspection described above. A
warm, uncompressed map is therefore not evidence of cold server restart
behavior, and none of these microbenchmarks establish restart convergence
or a production latency guarantee.
