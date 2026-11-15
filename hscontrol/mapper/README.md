# Composed property contracts

`TestRapidStreamSystem` drives one generated history through graph inputs,
public State requests, policy compilation, snapshots, `Route`, stream rendering,
JSON serialization through the actual Hub encoding cache in both uncompressed
and zstd modes, partial delivery and reconnect. Small focused properties
use the same components below. This is sampled contract testing, not an
exhaustive proof. Enabled diagnostic properties currently expose known bugs;
a failing aggregate is not a green acceptance suite.

Shared generators and reference models live in `hscontrol/propcheck`.
Package-local properties stay in the matching source test files; DNS reference
properties live in `propcheck/dns_test.go` so they can use the public DNS view
without creating a test import cycle.

## Reusable components

| Component                                                   | Focused callers                                                                                           | Composed caller and contract                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `propcheck.World`, `CheckWorld`, `WorldProbes`              | `state.TestWorldMutationProperty`, `TestWorldReferenceOwnership`                                          | `streamPropertySystem.checkWorld` after every write: owned node/user values, sorted membership, user ownership, node-key winners, machine-key buckets, retained old keys and snapshots. Native maps and scans; no graph, State, policy or mapper implementation imports.                                                              |
| `propcheck.DrawPolicy`, `ReorderPolicy`                     | `policy/v2.TestIncrementalPolicyRapidHistory`                                                             | `drawOperation` draws valid ACL/grant/SSH/capability/via policies, duplicates/reorders rules and restores earlier documents. The fleet supplies u1/u2/u3, tag:srv/router, and matching IPv4/IPv6 addresses. Duplicate app grants retain multiplicity. Known policy classifications survive reorder, duplicate and historical restore. |
| `propcheck.ElectRoutes`                                     | State route-election properties                                                                           | `checkWorld` predicts global winners after every write, preserving previous winners. Allow-all wire checks predict AllowedIPs and PrimaryRoutes. `TestRapidStreamRouteFailover` uses the same result for ordinary and tag:a via grants. Rich policy alias resolution remains a separate compiler oracle.                              |
| `propcheck.DrawDNSRecords`, `CanonicalDNSRecords`           | `propcheck.TestDNSViewProperty*`                                                                          | DNS operations and causal checks use the same record domain and normalization. Expected graph records and client records come from input; equivalent canonical records must not publish a revision.                                                                                                                                   |
| `wirePeers`, `wireUpgrade`, `wirePatchable`, `wireSemantic` | `TestRapidWire*`, `TestWireReachableFailures`, `TestPropertyClientContracts`                              | `propertyClient` uses the exact same pinned peer replay, including PeersChanged patchification. LastSeen is ignored only while Online is true. Zero DiscoKey, expiry clears and lost offline fields remain observable.                                                                                                                |
| `propertyClient`                                            | `TestPropertyClientContracts`, `TestRapidStreamModelPatchFields`, operation contracts                     | Tracks self, peers, named packet filters, SSH, DNS, DERP, domain, service collection, sticky profiles and a delta-only removal observer. Unseen owner profiles fail.                                                                                                                                                                  |
| `peerHistoryModel`                                          | `TestHubRapid*`, `TestPeerHistoryModel*`                                                                  | `open`, `update`, deletion and `checkHistory` share attempted/confirmed/retired/reconnect transitions. Simple-policy membership comes from World inputs; rich-policy membership comes from a separate fresh renderer, never the live stream's sent state. Hub class views may contain self; comparisons remove that non-wire member.  |
| `streamOperation`, `drawOperation`, `apply`, `checkCausal`  | `TestRapidStreamOperationContracts` selects endpoint/global, request/refusal and generated-policy subsets | The whole-system driver draws the same structured operations. Parameters are drawn before application. Model transitions, production application, delivery scheduling and checks are separate.                                                                                                                                        |

Graph transactions, persistent maps and concurrency properties remain local to
the graph package. Exporting their private test drivers would not add a shared
contract to this composition. Existing `TestHubCoalescedCommitsConverge`
exercises fixed graph subscription and Hub coalescing boundaries;
`TestRapidStreamSubscription` adds generated subscription histories using the
shared composed fixture and downstream checks described below. Existing
`TestStreamCatchesUpFromBeyondTheEditLog` exercises recovery beyond retained
history. These remain enabled rather than being copied into another driver.

## Input boundaries and expected effects

- **Graph-input adapter:** `PutNodeInStoreForTest` drives endpoint, Hostinfo,
  identity, key, expiry, route, health, copy and reversion changes. These are
  graph-input contracts, not registration, persistence, tag authorization or
  health-probe API coverage. Identical node copies still publish revisions.
  Reversion publishes both writes. Every intermediate write checks World and
  route election before coalesced delivery.
- **Public State requests:** generated endpoint/DiscoKey MapRequests use actual
  `UpdateNodeFromMapRequest`. Stale NodeKey requests and malformed policy
  documents must refuse without publication. Valid requests always publish
  LastSeen; its timestamp must fall within the request's measured interval
  before the reference adopts it. The substantive-report sequence is predicted
  independently. Endpoint/DiscoKey requests retain their original domain, including
  zero DiscoKey diagnostics. Hostinfo operations hold keys/endpoints and routes
  stable while varying reported names, OS, TCP services, requested tags and
  omitted/explicit NetInfo. `inputRequest` predicts normalized values from owned
  inputs before calling State; it never adopts a returned node as its oracle.
  Missing node IDs also refuse before publication. These refusal guarantees do
  not claim that persistence errors after publication are atomic.
- **Database fixture:** users have explicit IDs and timestamps. Nodes have real
  SQLite rows before request operations and graph publication. The DB clock is
  fixed per fixture. Direct graph edits are deliberately not advertised as
  durable DB writes. Default policy changes use in-memory `State.SetPolicy`,
  not the durable policy API. The explicit file fixture uses `State.ReloadPolicy`
  as described below.
- **Independent intent:** allow-all, deny-all and self/member policies predict
  peer membership from World. `checkStreamNodeInputs` checks self and peer
  identity, names, keys, tags, creation time and ownership against owned inputs.
  Packet-intent and simple-policy maps independently check own addresses;
  allow-all maps also predict subnet winners and approved exit routes. Rich policies use the shared
  structured generator, full-compile policy audits, focused incremental
  equivalence tests and fresh-render comparison; they do not have an independent
  general policy interpreter.
- **Causal deltas:** endpoint changes must deliver exactly the expected endpoint
  state without changing unrelated fields. Hostinfo checks hostname, services,
  peer OS and HomeDERP directly, allows the subject's platform-dependent fields
  to be freshly rendered, and preserves unrelated nodes/globals. DNS/DERP
  changes check generated output and unrelated fields. Copies, reversions and
  refusals preserve client semantics. Simple removal soundness applies under
  allow-all policy when deleting a node with no announced-and-approved routes;
  router/identity-dependent removals use route intent plus fresh convergence.
  Representation is flexible except documented standalone, sorted removal
  frames. Every checked snapshot repeat must be quiet.
- **Scheduling:** only Route-selected sessions wake at flushes; unwoken sessions
  must already be correct. Generated intermediate renders, coalesced writes,
  partial frame prefixes, disconnected sessions, reconnects and retired write
  confirmations share the same client and history models. Old snapshots are
  checked against owned World copies and old rendered client state.

## Replay

Run inside the repository dev shell. On the campaign host, retain its dedicated
`GOTMPDIR` and use `GOMAXPROCS=2` / `-p 1` to avoid competing with other builds.

```sh
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamSystem$' -count=1 -rapid.seed=20261115 -rapid.steps=10 -rapid.checks=20 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamOperationContracts$/^endpoints$' -count=1 -rapid.seed=20261116 -rapid.checks=300 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamOperationContracts$/^generated-policy$' -count=1 -rapid.seed=20261116 -rapid.checks=300 -rapid.nofailfile
go test -p 1 ./hscontrol/state -run '^TestWorldMutationProperty$' -count=1 -rapid.seed=20261116 -rapid.checks=300 -rapid.nofailfile
CGO_ENABLED=1 go test -race -p 1 ./hscontrol/mapper -run '^(TestPropertyClientContracts|TestRapidWireConnectivityReplay)$' -count=1 -rapid.seed=20261116 -rapid.checks=300
```

The broad stream property with seed 20261115 and request subset with seed
20261125 reproduce zero-DiscoKey loss. Existing deterministic diagnostics remain
enabled: `TestWireReachableFailures` (zero DiscoKey and offline LastSeen loss),
`TestStreamRouteOverlaySurvivesStaleCacheAndMembership` (lost route overlay), and
`TestIncrementalDuplicateAppGrantInvalidatesFilter` and
`TestIncrementalAppGrantOrderInvalidatesFilter` (stale reduced filters and
missed destination notifications after duplicate or reordered app grants).
`TestRouteWakesExitForCapabilitySource` pins a missed exit-node wake after a
normal endpoint request: app-only grants to public destinations intentionally
make the exit see its source without granting reciprocal visibility. Routing
must account for those consumers while preserving policy intent. Refactoring
must not make these diagnostics disappear.

## Remaining limits

The fixture keeps 3–8 live nodes and allocates monotonically increasing IDs
from 1 through 255. Deleted IDs remain probes and are never reused; additions
stop when the finite range is exhausted. This matches persistent node lifetimes
and prevents identity reuse from manufacturing a LastSeen clear. Lower-level
map/world branching properties retain their broader domains. The fixture uses
four capability-version boundaries.
There is no Noise/HTTP transport, real Tailscale process, PostgreSQL, process
restart, registration authorization, certificate issuance, or durable policy
failure/retry path in this driver. Hub TTL, capacity and concurrent session
limits are tested by the focused shared-ledger suite; this composition keeps
one live session per node and a fixed hub clock. Legacy PeerSeenChange,
OnlineChange, legacy DERP strings, unsigned peers and client Debug actions are
outside the generated wire domain. Pinned replay covers the modern fields
Headscale emits. Generated failures can stop a broad history early, so focused
component campaigns remain necessary.

## Shared DERP composition

`propcheck.DrawDERPMap` feeds structured policy `derpMap` fields and configured
DERP operations. `propcheck.EffectiveDERP` selects each region by explicit key
precedence and owns expected storage. `derp.TestApplyPolicyRapidReference` checks
that reference, input nonmutation, retained results and cloned policy regions.
It does not demand ownership of base regions or HomeParams from `ApplyPolicy`.

The stream driver derives effective DERP from configured inputs and the policy
JSON, checks snapshots after every write and compares delivered clients against
that independent expectation as well as fresh streams. Configured writes,
policy overlays, identical copies and historical restoration share the same
operations in `TestRapidStreamOperationContracts/derp` and the broad driver.
Configured publication follows complete input equality, and configured-only
global wakes follow effective equality. Policy document edits may additionally
wake every client for per-node rules; unchanged effective maps still emit no
DERP delta. Retained snapshots keep their old DERP value.
`TestRapidStreamDERPMaskedPublication` checks masked configured writes, ignored
policy scores, null removal and restoration without relying on random discovery.

Configured maps have explicit non-nil Regions with valid non-null regions;
empty Regions removes all relays. Policy overlays cover nil/empty, default-region
null deletion, custom regions 900 and 999, replacement, omit-defaults and ignored
HomeParams. Positive scores, empty scores and removed HomeParams remain in the
input domain. Nil configured maps are only focused ApplyPolicy boundary checks,
not an advertised post-start reload. Fetching, source merge and HTTP are covered
elsewhere. This component does not assert a general policy compiler oracle.

`TestStreamDERPScoreClearConverges` is an enabled diagnostic for configured
HomeParams/score clears. The pinned client retains omitted HomeParams or
RegionScore; JSON omitempty can therefore preserve stale scores after a clear.
Do not exclude these supported reload inputs to make a campaign pass. Stream
comparisons normalize absent/empty HomeParams and explicit score 1.0 to default
latency weights; every non-default score remains observable.

## Shared packet intent

`propcheck.PacketIntent` is a bounded input model shared by
`policy/v2.TestIncrementalPolicyRapidPacketIntent`,
`mapper.TestRapidStreamPacketIntent`, and `TestStreamPacketIntentHistory`.
`DrawPacketIntent` generates one to four directed TCP/UDP grants with wildcard,
user-name, tag or literal-IP selectors and inclusive port ranges. Each generated
replacement includes a live literal-IP witness. Explicit empty intent denies
all traffic. Expected permissions scan owned `propcheck.World` nodes and users;
tags exclude creator user rights even when UserID remains populated.

`CheckPacketIntent` checks both address families between distinct nodes. It
probes every port in each generated range, adjacent ports, ports 0 and 65535,
and denied port 32768 for both protocols. Wider manually constructed ranges
remain bounded: their first four ports, midpoint and endpoint are probed. Actual rules pass through the pinned Tailscale
`wgengine/filter.MatchesFromFilterRules`, `filter.New`, and `Filter.Check`.
TCP checks synthesize SYN packets; UDP checks start without outgoing conntrack.
The expected side never reads compiled policy, FilterRules or fresh rendering.
Allowed traffic requires reciprocal peer visibility. The shared checker returns
a necessary peer union for incoming and outgoing flows, checked only against the
viewer being validated; other sessions may legitimately lag. Denied packets do not imply absent
peers: same-user visibility remains unconditional.

The existing stream history stores immutable intent beside each policy document.
`packet-policy` and `packet-deny` are operations in the broad driver. Reorder,
duplicate, historical restore and DERP-only policy edits retain intent metadata;
unrelated richer policies clear it. The same check reads the client's cumulative
filter after JSON/delta replay and checks retained snapshots against their old
World and intent. Every successful open/update runs the same extracted
`checkSession` assertions: full fresh-snapshot comparison and existing independent
fields as well as packet intent. This includes intermediate deliveries later
restored within a coalesced batch. Batch-end `check` still validates unwoken
clients. Failed partial prefixes are checked only after successful reconnect.
The dedicated generated packet driver reuses the broad commit/delivery driver,
with six mandatory history phases and one to eight additional commits per case;
`-rapid.checks` extends that campaign. The broad driver retains `-rapid.steps`.
The fixed history keeps ownership revocation/restoration, document replacement,
deny/restore, membership and reconnect checks reachable independently of earlier
failures in broader generated histories.
After each fixed ownership revocation, destination 2 must complete that snapshot
before identity restoration: it reopens if disconnected or receives a complete
update otherwise. Both paths run `checkSession`; other deliveries retain random
partial prefixes. The memory and file fixtures share this guarantee.

The focused policy history evaluates both incremental and fresh managers against
intent and retains old managers/worlds. It deliberately does not use the older
byte-order equivalence helper: reordered packet grants can preserve authorization
while changing rule order. Existing representation checks and compiler audits
remain enabled and unchanged. `TestRapidStreamPacketIntent` currently reaches
that audit diagnostic on reordered packet grants; this does not by itself prove
an authorization mismatch. The original richer generator remains a secondary
compiler/fresh-render oracle, not an independent general policy interpreter.

```sh
go test -p 1 ./hscontrol/policy/v2 -run '^(TestIncrementalPolicyRapidPacketIntent|TestPacketIntentOwnershipAndPorts)$' -count=1 -rapid.seed=20261116 -rapid.checks=300 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestStreamPacketIntentHistory$' -count=1 -rapid.seed=20261116 -rapid.checks=20 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamPacketIntent$' -count=1 -rapid.seed=20261115 -rapid.checks=10 -rapid.nofailfile
```

This domain excludes self traffic, return traffic, external/subnet destinations,
CIDRs, groups, hosts, autogroups, ACL syntax, SSH, app capabilities and OIDC/email
alias resolution. It samples selected ports rather than every possible packet.
Full Tailscale processes and network transport remain outside this fixture.

## Successive policy files

`TestRapidStreamPolicyFiles` uses the same composed driver with file mode
selected before `State.NewState`. A valid deny document, its independent
`PacketIntent`, and accepted history agree before any session opens. Production
has one configured `Policy.Path`: this property replaces successive complete
files at that path, rather than merging simultaneous files.

`streamPropertySystem.inputPolicy` is the shared input adapter for `setPolicy`
and policy operations. File writes stage a small sibling file and rename it to
the configured path, then call `State.ReloadPolicy`. Staged bytes and intent are
owned separately from active expectations. Only acceptance advances the active
document and intent; the reference never derives them from graph or compiler
output. Per-attempt cleanup removes staged files together with the fixture DB.

The file domain composes packet replacements, explicit deny, reorder,
duplicates, prior accepted documents, identical bytes and equivalent HuJSON
comments. Staging without reload leaves graph and consumers unchanged. Malformed
syntax, empty and missing files, and a valid document with a failing embedded
TCP test must refuse without publication. The embedded test uses live literal
addresses, so user renames cannot make it vacuous. Repeated reloads of refused
files remain refused; replacing them with accepted bytes restores normal
operation. World checks preserve input-owned route approvals through every
reload, including accepted policy changes.

The existing Route, Stream, Hub JSON/zstd replay, cumulative client, peer ledger,
retained snapshots and per-delivery `checkSession` checks remain in use.
Staging, same-byte reloads, equivalent comments and refusals additionally preserve
the prior consumer state and require no delta, including a repeated quiet
update. Comment edits still publish changed raw source bytes and a new revision.
Batch-end checks include unwoken clients; partial prefixes are checked
after reconnect. All policy audit diagnostics remain enabled.

`TestStreamPolicyFileHistory` reuses the fixed packet history with one-grant
documents and explicit staging, successful reload, refusal and restoration
phases. It keeps those contracts reachable even when generated multi-grant
histories stop at known compiler diagnostics. The generated file history adds
eleven file-boundary phases to the existing six packet phases, then one to eight
additional commits; each commit coalesces one to three operations.
Seed 20261115 completes the file-boundary phases, then reaches the existing
reordered-packet filter audit diagnostic. That failure remains enabled; it does
not by itself establish an authorization mismatch.

```sh
go test -p 1 ./hscontrol/mapper -run '^TestStreamPolicyFileHistory$' -count=1 -rapid.seed=20261115 -rapid.checks=20 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamPolicyFiles$' -count=1 -rapid.seed=20261115 -rapid.checks=10 -rapid.nofailfile
CGO_ENABLED=1 go test -race -p 1 ./hscontrol/mapper -run '^TestStreamPolicyFileHistory$' -count=1 -rapid.seed=20261116 -rapid.checks=10 -rapid.nofailfile
```

This tests explicit reload of complete replacements. It does not cover a file
watcher, signal delivery, concurrent OS partial writes, crash durability,
server restart, or a multi-file merge API. Default DB fixtures and their existing
in-memory policy behavior remain unchanged.

## Independent node projection

`checkStreamNodeInputs` checks every delivered self and peer against owned
`propcheck.World` inputs. It runs in `checkSession` after every completed
delivery, including intermediate maps, and on retained full and late maps using
their old World and policy-domain flag. The base domain is fixed by the fixture
at construction. Expected names use GivenName plus that domain and a trailing
dot; without a base domain, the name is the bare GivenName. Neither fresh
renders nor `TailNode`, `GetFQDN` or ownership projection helpers supply the
expected values.

The contract includes numeric ID, decimal StableID, name, NodeKey, DiscoKey,
tags, Created as an instant, and user-versus-tag ownership. Tagged peer ownership
ignores the creator; tagged self ownership uses its isolated user ID. Self must
remain authorized and unexpired, with zero Cap and absent Online/LastSeen.
`TestStreamNodeInputContracts` supplies literal examples for both viewer roles,
non-UTC creation input, expired/online input, empty/nonempty domains, separate
IPv4-only and IPv6-only nodes, and a router with an additional subnet route.

For PacketIntent documents and simple policy kinds 0–2, which have no
disable-ipv4 attribute, exact Addresses come from owned IPv4/IPv6 and every own
identity prefix must appear in AllowedIPs. AllowedIPs may also contain routes;
the existing route oracle checks those separately. Rich node-attribute policies
retain fresh-render address checks until independent attribute intent exists.
Peer capability versions, connectivity, expiry and Hostinfo projection remain
outside this helper; existing causal and fresh-render checks still apply.

```sh
go test -p 1 ./hscontrol/mapper -run '^TestStreamNodeInputContracts$' -count=1
go test -p 1 ./hscontrol/mapper -run '^(TestStreamPacketIntentHistory|TestStreamPolicyFileHistory)$' -count=1 -rapid.seed=2026111562 -rapid.checks=30 -rapid.nofailfile
```

## Public MapRequest histories

`TestStreamMapRequestHistory` composes the existing operation adapter, World and
route references, Route-selected delivery, Hub JSON/zstd encoding, cumulative
client and full session checks in both DB and real policy-file fixtures.
Mandatory phases establish reports, repeat them, omit Hostinfo, omit NetInfo,
replace DERP 1 with 2, explicitly clear DERP to 0, report an empty hostname and
withdraw, re-advertise and withdraw routes again. Report, DERP-clear and route
phases complete every consumer before the next transition. Other phases and
generated coalesced suffixes retain partial delivery and reconnects. Deny/allow policy replacements
interleave with the generated request batches; file mode performs real reloads.
Unwoken sessions are still checked, so this does not force wakes to conceal
Route failures.

The input reference preserves stored Hostinfo on omission and stored NetInfo
when only NetInfo is omitted. Explicit NetInfo replaces it, including DERP 0.
Supported nonempty hostnames are short DNS-safe per-node labels: automatic
GivenName follows them, custom names stay unchanged, and empty reported names
preserve Node.Hostname/GivenName. Generated reports use the current Node.Hostname
unless explicitly changing it; older direct-graph Hostinfo operations can leave
the two hostname fields inconsistent and do not define collision-free requests. Reported RequestTags never grant effective tags
or change ownership. Identical reports change only measured LastSeen, without
advancing the independently predicted substantive-report sequence.

The route domain uses canonical, distinct IPv4 subnet prefixes. The focused
fixture seeds manual and automatic approval provenance, then exercises public
advertisement/withdrawal under policies without auto-approvers. Manual approvals
survive withdrawal; withdrawn automatic approvals disappear; no announced and
approved route means stale Unhealthy clears. Re-advertisement does not restore
removed automatic approval. Broad Hostinfo operations preserve advertisements
because richer policies contain auto-approvers outside this reference domain.
An unsupported route-changing policy fails an explicit precondition rather than
silently skipping a case or adopting production approvals. The file history also
composes a valid commented policy with a route-changing request: raw active,
modeled and retained policy bytes stay unchanged, and only the node write publishes.

Every accepted request is checked for caller nonmutation. After acceptance the
adapter overwrites its submitted Hostinfo, NetInfo, service/tag/route slices and
endpoint buffers, then checks current and retained snapshots against separately
owned World values. Golden phase assertions anchor automatic/custom names, tag
ownership, approval provenance and health. The focused operation subset
`TestRapidStreamOperationContracts/request-hostinfo` reuses the same generator
and adapter under the existing policy fixtures.

This domain excludes DERP latency jitter, arbitrary hostname sanitation and
collisions, route duplicates, general auto-approver policy evaluation, tag claim
authorization, persistence failure/retry and concurrent request ordering. The
existing State tests cover additional normalization cases. It does not change
the enabled broad-domain wire or policy diagnostics.

```sh
go test -p 1 ./hscontrol/mapper -run '^TestStreamMapRequestHistory$' -count=1 -rapid.seed=2026111571 -rapid.checks=30 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamOperationContracts$/^request-hostinfo$' -count=1 -rapid.seed=2026111572 -rapid.checks=100 -rapid.nofailfile
CGO_ENABLED=1 go test -race -p 1 ./hscontrol/mapper -run '^TestStreamMapRequestHistory$' -count=1 -rapid.seed=2026111573 -rapid.checks=10 -rapid.nofailfile
```

## Generated subscription bridge

`TestRapidStreamSubscription` bridges owned input histories through the real
State graph subscription, `Hub.watch`, and `Session.Wakes`. It reuses
`streamPropertySystem`, its operations and input adapters, complete `update`
delivery, Hub JSON/zstd framing, cumulative client replay, World/node checks,
route election, and the peer-history ledger. Each completed intermediate map
runs `checkSession` before later writes can hide an incorrect delivery.

Three bounded domains run separately: endpoint copies/changes/reversions under
one simple policy; simple-policy replacements/reversions; and mixed bursts.
Policies are allow-all, deny-all and member-to-self. Each history has zero to
four prefix operations, optional completed intermediate consumers, and a
mandatory positive witness. Endpoint witnesses use same-user nodes 1 and 4;
policy witnesses use viewer 1, which always has same-user and cross-user peers.
The fixture adds node 4 when its original fleet has only three nodes. Endpoint
and policy reversion domains restore the watcher's original semantic inputs
while a consumer retains a completed intermediate map.

The required-wake model owns each viewer's last completed input projection:
self and independently visible peer endpoints, peer membership, and directed
live-node packet permission bits. Simple-policy visibility reuses the existing
World-based reference. Permission bits follow the three literal policy intents,
not compiled filters. A difference from final input requires a wake. The model
never reads Route decisions, live Stream sent state, cache revisions or rendered
outputs. This is a necessary-wake lower bound; additional conservative wakes
are accepted. Endpoint lists are copied, and nil/empty lists are equivalent.

The subscription starts before the batch, but the watcher starts only after all
writes and intermediate deliveries complete. Empty session wake channels are
asserted before starting it. A Rapid synctest bubble owns the fixture and all
channels; `synctest.Wait` establishes quiescence after enqueue, rather than
assuming `hub.latest` advancement means wakes were sent. Missing required wakes
fail immediately without sleeps or a timing oracle. Only actual received wakes
trigger final delivery. Every unwoken client must already satisfy the same final
checks. The original World snapshot is checked against its retained owned copy.
Every attempt closes and joins the watcher and closes its subscription, even
when Rapid shrinks a failure. There is no global barrier write.

```sh
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamSubscription$' -count=1 -timeout=10m -rapid.seed=2026111570 -rapid.checks=100 -rapid.nofailfile
CGO_ENABLED=1 go test -race -p 1 ./hscontrol/mapper -run '^TestRapidStreamSubscription$' -count=1 -timeout=10m -rapid.seed=2026111571 -rapid.checks=20 -rapid.nofailfile
```

This bridge does not model partial delivery, reconnect, membership deletion,
history overrun, TTL/capacity, arbitrary policies, concurrent MapRequests, or
transport timing. Existing properties retain those separate domains. Deletion
is deliberately excluded because the shared operation adapter manually forgets
sessions, which would mask watcher cleanup. No socket, HTTP, Noise or Tailscale
process is exercised, and quiescence establishes no latency/performance claim.
