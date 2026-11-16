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
  peer membership and sampled TCP/UDP permissions from World. `checkStreamNodeInputs` checks self and peer
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

`CheckPacketIntent` checks both address families between distinct live nodes,
plus the bounded source-address probes described below. It
probes every port in each generated range, adjacent ports, ports 0 and 65535,
and denied port 32768 for both protocols. Wider manually constructed ranges
remain bounded: their first four ports, midpoint and endpoint are probed. Actual rules pass through the pinned Tailscale
`wgengine/filter.MatchesFromFilterRules`, `filter.New`, and `Filter.Check`.
TCP checks synthesize SYN packets; UDP checks start without outgoing conntrack.
The expected side never reads compiled policy, FilterRules or fresh rendering.
Allowed traffic between live nodes requires reciprocal peer visibility. The shared checker returns
a necessary peer union for incoming and outgoing flows, checked only against the
viewer being validated; other sessions may legitimately lag. Denied packets do not imply absent
peers: same-user visibility remains unconditional.

The existing stream history stores immutable intent beside each policy document.
When explicit packet intent is absent, `streamPacketIntent` interprets only
the three literal simple-policy fixtures: wildcard allow-all, explicit deny-all,
and member-to-self using each current owned user's name. TCP and UDP cover ports
0–65535 with the bounded probes above. Tagged nodes never inherit creator
permissions. This temporary intent is rebuilt for each check, never stored in
policy metadata; retained full and late maps share intent captured from their
old World and policy before writes. Rich policies retain the existing
fresh-render boundary unless they carry explicit input intent.
`TestStreamSimplePolicyIdentityHistory` checks same-user permission through
rename, tag revocation, restoration and deny, while retaining the old self-policy
map. `TestRapidStreamSimplePolicyEdits` checks delivered permissions after
reordering, duplication and historical restoration of each simple policy.

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

The generated packet domain excludes self traffic, return traffic,
external/subnet destinations, CIDRs, groups, hosts, general autogroups and ACL
syntax, SSH, app capabilities and OIDC/email alias resolution. Only the three
literal ACL fixtures above receive the simple-policy fallback. These checks
sample selected ports rather than every possible packet.
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

The same helper checks every currently required owner profile against owned
`World.Users`: ID, LoginName, DisplayName, ProfilePicURL and empty Groups.
LoginName takes the first nonempty email, name, provider identifier string or
decimal ID; an empty display name falls back to that login. Expected values
never call production user projection helpers. Tagged peers require the literal
global Tagged Devices profile. Tagged self additionally requires its isolated
profile, with the input FQDN minus its trailing dot and GivenName as display.
Literal fixtures cover these fallbacks, both viewer roles and tagged self alone.
Historical profiles may remain cached; the existing unseen-owner ledger still
rejects profiles of owners never visible to the client.

`TestStreamProfileInputHistory` runs DB and file fixtures through rename, display
and picture changes, explicit clears, tagging, denial, hidden presentation edits,
visibility restoration and untagging. Each phase completes Route-selected
consumers and checks unwoken clients before restoration. Display/picture edits
leave the policy document unchanged. Retained maps use their old World and direct
old-snapshot rendering. Zero to three generated user edits follow the mandatory
history; the shared user generator now includes nonempty and cleared pictures.
Generated histories retain CLI names and display/picture fields; email/provider
fallbacks are literal checker contracts, not expanded policy alias domains.

```sh
go test -p 1 ./hscontrol/mapper -run '^TestStreamNodeInputContracts$' -count=1
go test -p 1 ./hscontrol/mapper -run '^TestStreamProfileInputHistory$' -count=1 -rapid.seed=2026111584 -rapid.checks=20 -rapid.nofailfile
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

## Ordered application capability intent

`propcheck.AppIntent` owns an ordered list of custom `AppGrant` inputs. It shares
`PacketSelector` matching and tag-versus-user ownership with `PacketIntent`.
`AppIntent.Document` composes both inputs; app-only documents carry an explicit
empty packet intent, so the packet checker also proves they grant no TCP/UDP
ports. Mixed documents use the existing packet oracle without redefining it.
These peer capabilities are distinct from `Node.CapMap` and network permissions.

`DrawAppIntent` includes a live literal-IP witness, then zero to three grants
using wildcard, user, tag or literal-IP selectors. The bounded custom keys are
under `example.com/cap/`; payloads are canonical JSON objects with ordered and
possibly repeated values. Nil and empty value lists both retain capability-key
presence. `Capabilities` scans only owned World identities and grant inputs.
`CheckAppIntent` evaluates delivered FilterRules using the pinned Tailscale
`Filter.CapsWithValues`, compares every returned key and each ordered value,
and requires matching sources to be visible to their destination. It does not
require reciprocal visibility for app-only grants. Empty intent still checks
all current node pairs and bounded source probes, catching retained revoked capabilities.

App metadata follows the same active/staged policy records, file reloads,
comments, historical restores, DERP-only changes and old snapshots as packet
intent. Unrelated richer documents clear both metadata fields. Reorder and
duplicate operations create a new ordered app intent and serialize its grants;
they never reuse stale expected order or derive expectation from compiled rules.
Unrelated document fields, including DERP overlays, survive these transformations.

The shared incremental policy history checks retained, warm and fresh managers
independently against both input models. `TestIncrementalPolicyRapidAppIntent`
keeps order/duplicate diagnostics enabled; `TestIncrementalPolicyRapidAppReplacements`
keeps value replacements, denial, restores and generated identity/family changes
reachable without those earlier diagnostics. `TestAppIntentOwnershipAndValues`
anchors the model with literal ownership, family, key-presence and ordered-value
expectations. Corruption controls reject dropped capabilities, retained revoked
capabilities, reversed or duplicated payloads, and substituted empty-valued keys,
even without a warm/fresh comparison.

`TestRapidStreamAppIntent` reuses the whole-system scheduler and both DB and
real file backends. Every completed delivery and retained snapshot runs the same
app check alongside packet, projection and fresh-map checks. The fixed
`TestStreamAppIntentHistory` reaches value replacement, clear/restore, mixed
packet/app policies, staging/reload/refusal, ownership revocation and DERP edits.
It checks unwoken live clients before reconnecting a partially delivered
destination, and completes destination 2 before restoring a revoked state.

`TestIncrementalAppIntentConsumerInvalidation` strengthens the existing production
bug evidence: a warmed destination receives `[read, write]` after input changes
to `[write, read]`, and `[read]` after input changes to `[read, read]`. Fresh
managers satisfy intent. These are observable order/multiplicity defects, not
new bug classes or claims of opened network ports. Existing audits and enabled
failing properties remain intact; aggregate results are deliberately diagnostic.

```sh
go test -p 1 ./hscontrol/policy/v2 -run '^(TestAppIntentOwnershipAndValues|TestAppIntentRejectsCorruptedConsumerRules|TestIncrementalPolicyRapidAppReplacements)$' -count=1 -rapid.seed=2026111571 -rapid.checks=300 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestStreamAppIntentHistory$' -count=1 -rapid.seed=2026111571 -rapid.checks=20 -rapid.nofailfile
go test -p 1 ./hscontrol/policy/v2 -run '^TestIncrementalAppIntentConsumerInvalidation$' -count=1
```

The domain excludes companion capabilities, via and public/subnet destinations,
nodeAttrs capabilities, general aliases and self traffic. Historical source
coverage has the explicit bound below. Full clients, network
transport and application-specific interpretation of JSON remain outside scope.

## Generated subscription bridge

`TestRapidStreamSubscription` bridges owned input histories through the real
State graph subscription, `Hub.watch`, and `Session.Wakes`. It reuses
`streamPropertySystem`, its operations and input adapters, complete `update`
delivery, Hub JSON/zstd framing, cumulative client replay, World/node checks,
route election, and the peer-history ledger. Each completed intermediate map
runs `checkSession` before later writes can hide an incorrect delivery.
That shared check independently validates delivered simple-policy TCP/UDP
permissions and necessary incoming/outgoing peers, including final unwoken
clients; the required-wake model below remains a separate input reference.

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

## Independent SSH authorization intent

`propcheck.SSHIntent` owns immutable grants with one user or tag source and one
explicit tag or `Self` destination. It reuses `PacketSelector` ownership: tagged
nodes do not inherit their creator's user permissions, and self means devices
owned by the same user. Check and self sources are user-only. Logins are explicit
`root`, `alice` and `bob`; `charlie` and numeric `0` remain denied. Check dominates
accept regardless of input rule order. `Decision` reads only those inputs and
`World`, never compiled policy, fresh output or Headscale's SSH test evaluator.

`AppendDocument` adds the SSH rules and missing tag declarations to an existing
packet/app document. Explicit empty packet intent checks that SSH-only documents
deny the bounded TCP/UDP probes between distinct nodes. Empty app intent also checks capability denial. Mixed
histories carry all three intents; unrelated policy replacements clear the SSH
metadata. `streamSSHIntent` derives empty authorization from owned documents whose
SSH rules are absent, null or empty, so replacement still checks denial. Nonempty
unmodeled SSH rules retain the existing audit/fresh-render checks. The fallback
is captured before writes for retained maps and never changes policy metadata or
input bytes. Active, staged, restored, commented, reordered, duplicated and DERP-only
documents retain the corresponding immutable intent. Historical checks retain
both the old World and old intent; late rendering uses `r.render(old)` plus
`fullResponse`, because `Initial(old)` may intentionally advance to Hub's latest
snapshot.

The pinned Tailscale evaluator is unexported. `CheckSSHIntent` instead checks a
small, strict interpretation of the delivered protocol. Its source contracts are
[`tailcfg.SSHPolicy`, `SSHRule`, `SSHPrincipal` and `SSHAction`](https://github.com/tailscale/tailscale/blob/f7c1b8e52600/tailcfg/tailcfg.go#L2672)
and [`matchRuleWithUserLookup` / `mapLocalUser`](https://github.com/tailscale/tailscale/blob/f7c1b8e52600/ssh/tailssh/tailssh.go#L1608).
Rules are first-match; principals match individual NodeIP addresses, empty exact
login mappings do not match, reject bypasses login matching, and accept/delegate
remain distinct. Whole-struct shape checks reject other principal fields,
expiration, environment rules, recording and unsupported action fields. The
check URL must use the configured ServerURL and known substitution placeholders;
SessionDuration must be zero. Check periods are server-side, not session limits.
Wildcard and `=` mappings are rejected, so no OS-account or root-UID assumption
is hidden in the checker. The high-level check precedence and self semantics
follow the [SSH policy contract](https://tailscale.com/docs/reference/syntax/policy-file#ssh).

Checks cover every live source address, including source equal to destination,
all five probe logins, two reserved foreign addresses, and every emitted
principal address. An emitted address absent from World must deny, covering
stale deleted sources and arbitrary foreign broadening. Literal protocol rules
anchor accept, delegate, empty denial and reject precedence. Corruption controls
call the same checker and require its assertion panic and message: dropped
principal/login, broadened root/foreign address, deleted source, stale revoked
rules, accept before check, wildcard/Any fields, wrong delegate URL and duration.
They do not rely on warm/fresh disagreement.

`TestIncrementalPolicyRapidSSHIntent` shares the incremental packet/app history
and checks old, warm and fresh managers independently, including both server
URLs, identity/address-family changes, reorder/duplicate and replace/deny/restore.
`TestRapidStreamSSHIntent` shares the composed DB/file driver and keeps all audit
diagnostics enabled. Every completed session map is checked before later writes.
`TestStreamSSHIntentHistory` keeps fixed positive phases reachable: competing
accept/check rules, login replacement, clear/restore, packet/app composition,
staging/reload/refusal, source/destination ownership changes, DERP edits,
reorder/duplicate and source deletion. Unwoken clients are checked before any
forced reconnect; all destinations finish revoked states before restoration.
Its SSH-only tagged destination has no ordinary peers.

```sh
go test -p 1 ./hscontrol/policy/v2 -run '^(TestSSHIntentOwnershipAndProtocol|TestSSHIntentRejectsCorruptedRules|TestIncrementalPolicyRapidSSHIntent)$' -count=1 -rapid.seed=2026111591 -rapid.checks=300 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestStreamSSHIntentHistory$' -count=1 -rapid.seed=2026111591 -rapid.checks=20 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamSSHIntent$' -count=1 -rapid.seed=2026111591 -rapid.checks=3 -rapid.nofailfile
```

This is control-plane authorization evidence, not a successful SSH connection.
It excludes literal-IP selectors, general aliases, nonroot/localpart, local
account databases, posture, authentication callbacks, check cookies, recording,
OS behavior and network processes. The strict emitted shape deliberately fails
if the compiler starts emitting another form; extend the documented protocol
domain before accepting it. No production behavior or subscription fixture is
changed.

## Shared node-attribute intent

`propcheck.NodeAttrIntent` shares the owned World and user/tag/wildcard
`PacketSelector` domain with packet intent. Its immutable grants contain only
`custom:probe`, `custom:other`, `randomize-client-port`, and `disable-ipv4`.
Each generated replacement includes a live witness. The fixed four-key universe
keeps denied and revoked keys observable even when current intent is empty.
`AppendDocument` preserves packet/app/SSH grants, DERP overlays and existing tag
owners; reorder and duplicate operations retain immutable historical intent.

`TestIncrementalPolicyRapidNodeAttrIntent` extends the shared policy history:
old, incremental and fresh managers are checked against owned inputs through
identity/family changes, replacements, clears, restoration and duplication.
`TestRapidStreamNodeAttrIntent` uses the existing composed DB/file driver,
including staged files, failed reloads, comments, DERP edits and retained maps.
Mixed documents retain packet/app/SSH diagnostics; those known failures remain
enabled and can stop generated histories before later attribute checks.

`checkStreamNodeInputs` checks delivered self marker membership and requires
those markers to be absent from peers. Baseline capabilities are outside this
four-key comparison. Compiler and raw wire markers have null payloads;
`CheckNodeAttrWire` checks the existing encoding/replay adapter before replay.
The pinned `tailcfg.Node.Clone` turns nil capability slices into empty slices,
so the consumer checker requires empty payloads while preserving key presence.
The helper treats simple/owned packet documents without attribute metadata as
empty attribute intent; unmodeled rich policies remain outside this oracle.

IPv4 self identity depends on the node's own flag. Peer identity depends on
either the peer's or viewer's flag. IPv6 remains present. The allow-all route
check still predicts subnet winners and exit prefixes from owned route inputs;
removing IPv4 identity must not remove advertised IPv4 subnet or exit routes.
Packet intent continues to describe ACL permission on World IPs, not actual
link connectivity after address suppression.

`TestStreamNodeAttrIntentHistory` guarantees completed enable/clear/restore and
ownership phases for both DB and actual policy-file fixtures. Two viewers with
different flags reuse one Hub peer cache. A routed peer retains its IPv4 subnet
and exit routes. Route-selected sessions and unwoken clients are checked before
reconnect; retained maps use old inputs and direct rendering. Literal node
contracts also corrupt actual shared-checker inputs to prove detection of
missing/stale/peer-leaked markers, IPv4 identity leaks and IPv6 loss. Separate
marker controls cover unexpected keys, nonempty payloads and raw non-null values.

This is a bounded marker oracle, not a general nodeAttrs interpreter: no IP
selectors, groups, aliases, IP pools, companion data, parameterized capabilities,
top-level randomizeClientPort, or baseline-capability model. Input slices are
immutable after construction; transformations copy the outer grant slice only.

## Public control sessions and expiry

`TestRapidStreamControlSessions` reuses `runRapidStreamSystem` with public
`State.Connect`, `ConnectForMapRequest`, `Disconnect` and `SetNodeExpiry`
operations. DB and policy-file histories retain the same World, election,
Route-selected delivery, Hub JSON/zstd encoding, partial delivery, reconnect
and retained-snapshot checks. Existing graph-input histories keep their domain.

An opt-in control ledger records every acquired epoch per node. The fixture's
synthetic router session is explicitly normalized to zero before activation;
subsequent counts come only from successful public acquisitions. Every acquired
lease is released exactly once, in generated order, including final draining.
Epochs identify leases; they do not impose release order. Hub/map-delivery
sessions remain separate from these logical control leases. The component does
not claim to exercise the HTTP poll handler's acquisition/release wiring.

The adapter predicts SessionEpoch, ActiveSessions, Online, unhealthy clearing
and unchanged fields from owned World inputs. First admission and final release
validate SessionStart and LastSeen against their measured API call intervals,
then adopt only those timestamps. Stale/zero keys and missing nodes refuse
without publication. Direct graph online, key, identity, deletion, addition and
expiry edits are rejected while the ledger is active; endpoint/Hostinfo,
policy, DNS and DERP histories still compose. This restriction prevents direct
count edits or deleted leases from masquerading as supported transport events.

Expiry inputs are nil, zero, far-past year 2000, far-future year 9999 and a
non-UTC future date. Expected UTC normalization comes from the submitted value.
Years outside the wire range refuse before publication. Caller pointer reuse
must not mutate current or retained snapshots. Memory-first DB error behavior
is outside the domain; successful calls do not establish restart durability.

`checkStreamConnectivityInputs` independently checks delivered KeyExpiry,
Expired, Online, offline LastSeen, Endpoints and HomeDERP beside the existing
identity projection. Every completed current map and retained/late map uses
its own captured World. Expired peers with active control sessions retain
Online=true for NeedsLogin but lose endpoints and DERP; expired self retains
connectivity and has Expired=false, absent Online and absent LastSeen. LastSeen
is ignored only while Online=true, matching pinned sticky replay. Offline
fields, zero DiscoKey and expiry-clear diagnostics remain observable.
`TestStreamConnectivityInputContracts` anchors literal self/peer examples;
`TestStreamConnectivityRejectsCorruptions` proves that the actual checker
rejects lost expiry, wrong online/expired state, retained expired connectivity,
lost or stale offline timestamps and wrong self overrides.

`TestStreamControlSessionHistory` guarantees overlapping sessions, release of
the newer epoch before the older final release, final offline state, expired
admission, expiry clear/restore while connected, refusal cases and two-router
failover. All Route-selected consumers complete each phase, and unwoken clients
are checked before reconnect. The existing independent route reference remains
authoritative: when no router is available, an approving incumbent remains the
global fallback. Expired/offline does not imply route withdrawal. Both backends
retain old World/snapshots and re-render them after each transition.

```sh
go test -p 1 ./hscontrol/mapper -run '^(TestStreamConnectivityInputContracts|TestStreamConnectivityRejectsCorruptions|TestStreamControlSessionHistory)$' -count=1 -timeout=10m -rapid.seed=2026111613 -rapid.checks=20 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestRapidStreamControlSessions$' -count=1 -timeout=10m -rapid.seed=2026111612 -rapid.checks=20 -rapid.nofailfile
```

The generated file campaign can expose the existing DERP score-clear diagnostic
(reproduction seed 2026111690); that supported input remains enabled. This
component excludes real clock-crossing expiry sweeps, reauthentication,
registration, SSH callbacks, ephemeral GC, concurrent transport ordering and
DB failure/retry. It adds no production changes or new clock model.

## Bounded retired and foreign source addresses

`CheckPacketIntent` and `CheckAppIntent` accept optional `extraSources ...netip.Addr`
from owned operation inputs. Both checkers merge these with all current node
addresses and two never-owned probes, `100.64.255.254` and
`fd7a:115c:a1e0::ffff`. A shared input scan deduplicates addresses and resolves
each address to its owner in the supplied World, or anonymous ID 0 when absent.
Retained maps use their retained World, not current identities. A removed IP
family does not retain the surviving node's user or tag identity. Self-address
probes stay excluded. Anonymous sources never become required peers.

User and tag selectors deny an absent identity. Literal-IP selectors still
match their address, and wildcard selectors still match the bounded address
domain. This is deliberately not unconditional denial after deletion. The
source contract is `Username.resolve`, `Tag.resolve`, `Prefix.resolve` and
`asterixResolved` in `policy/v2/types.go`: wildcard covers CGNAT and Tailscale
ULA addresses, excluding the ChromeOS VM range. These probes stay within that
domain; wildcard is not arbitrary Internet authorization. The pinned filter's
`Check` and `CapsWithValues` remain the only actual consumers. These assertions
measure filter predicates, not reachable packets, connections or applications.

The stream fixture records both input addresses at creation for its first eight
node lifetimes (IDs 1 through 8). It never evicts a retained witness. All current
node pairs remain checked, including later lifetimes, but retired addresses from
IDs above 8 are outside this historical bound. Existing creation inputs assign
fixed addresses per ID; the focused incremental history accumulates each of its
four to six nodes' input addresses as families appear or disappear (at most 12).
No probe is taken from a compiler rule or production snapshot.

At most 16 historical addresses plus two reserved addresses are added per stream
map, independent of the possible 255 lifetimes. Deduplication removes live-address
overlap. Each compatible source adds two protocol checks per existing packet
port and one app-capability lookup; each checker constructs its consumer only
once. Generated packet grants retain 28 fixed port probes, so the upper added
packet cost is 1,008 checks per dual-stack destination (18 × 2 × 28), before
manual-range probes. App checks add at most 18 lookups. This is test-time cost,
not a production-performance claim.

`TestPacketAppIntentRetiredSources` anchors both families, user/tag deletion,
family removal, address reassignment, restoration, raw-IP/wildcard controls and ordered app payloads.
It feeds stale identity rules to the same actual checkers and requires assertion
failure; the original raw-address rules must still pass after deletion.
`TestStreamAppIntentHistory` composes packet and app grants through both DB and
real-file policies, deletes user source 1 and tagged source 3, and completes
destination 2 before replacing revoked identity grants with literal/wildcard
controls. Its existing flush checks unwoken clients before reconnect. All old
packet-port, ownership, SSH-absence, attribute and online projections remain.

```sh
go test -p 1 ./hscontrol/policy/v2 -run '^(TestPacketAppIntentRetiredSources|TestIncrementalPolicyRapidPacketIntent|TestIncrementalPolicyRapidAppReplacements)$' -count=1 -rapid.seed=2026111621 -rapid.checks=300 -rapid.nofailfile
go test -p 1 ./hscontrol/mapper -run '^TestStreamAppIntentHistory$' -count=1 -rapid.seed=2026111621 -rapid.checks=20 -rapid.nofailfile
```

## Concurrent policy and DNS inputs

`TestRapidStreamConcurrentInputs` composes two public inputs on one shared State:
`SetPolicy` with the existing allow-all, deny-all or member/self document, and
`SetExtraRecords` with owned DNS records. This is the memory-only policy API;
concurrent file reload and durable policy writes are outside this domain.
Nodes and users remain fixed. `world.SetPolicy` writes only the policy source
cell, while `world.SetExtraRecords` replaces records in the DNS cell and retains
its frozen settings. These simple documents do not read DNS or contain route
auto-approvers, embedded tests or SSH callbacks. Either publication order must
therefore preserve both inputs. No production timestamp or report-generation
assignment is adopted.

The complete bounded history is drawn before workers start. Each pair launches
two goroutines behind one start channel; both public calls finish before the
owned model advances or Rapid asserts. Scheduler interleavings are not guaranteed
or made deterministic by the seed. Mandatory phases cover simultaneous positive
changes, canonical DNS no-op, completed denial and clear, empty no-op,
restoration, policy-only change and DNS-only change. Up to four generated pairs
follow. Policy acceptance and the exact sum of independent graph revisions are
checked; equivalent pairs must publish no revision and enqueue no session wake.
Submitted buffers are checked for mutation and then overwritten to test ownership.

An actual State subscription and Hub watcher run throughout the history inside
`rapid.SyncTest`. After both writers finish, `synctest.Wait` establishes wake
enqueue quiescence. Only received session wakes cause delivery. Every completed
map and every unwoken client passes the existing `checkSession`, owned packet,
identity, connectivity, World, route and peer-history checks. Encoding still uses
both Hub JSON/zstd cache slots and pinned client replay. DNS ExtraRecords derive
from `propcheck.CanonicalDNSRecords`; all other DNS fields must preserve the
completed baseline settings. That latter comparison checks preservation, not an
independent startup DNS renderer. Policy audits remain enabled.

Each pair retains the pre-burst World, snapshot, policy, DNS records and a full
client map. After the burst, the retained map and a late render of the old snapshot
pass the old input checks. Late rendering uses `r.render` plus `fullResponse`,
because `Initial` may advance to the Hub's latest snapshot. Literal positive and
cleared protocol maps in `TestStreamConcurrentInputContracts` anchor the same
packet and DNS checkers. Five corruption controls reject lost policy, lost DNS,
stale policy, stale DNS and lost frozen settings without a fresh-render oracle.

```sh
go test -p 1 ./hscontrol/mapper -run '^(TestRapidStreamConcurrentInputs|TestStreamConcurrentInputContracts)$' -count=1 -timeout=10m -rapid.seed=2026111602 -rapid.checks=100 -rapid.nofailfile
CGO_ENABLED=1 go test -race -p 1 ./hscontrol/mapper -run '^(TestRapidStreamConcurrentInputs|TestStreamConcurrentInputContracts)$' -count=1 -timeout=10m -rapid.seed=2026111603 -rapid.checks=20 -rapid.nofailfile
```

This is final quiescent convergence for independent public writes. It does not
check maps delivered during a burst, establish full linearizability, guarantee
particular lock schedules, or cover concurrent MapRequests, transport, database
failure/retry, or restart durability. No generic scheduler or production hook is
introduced. Existing sequential and known-failing domains remain unchanged.
