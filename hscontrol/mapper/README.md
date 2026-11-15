# Composed property contracts

`TestRapidStreamSystem` drives one generated history through graph inputs,
public State requests, policy compilation, snapshots, `Route`, stream rendering,
JSON serialization through the actual Hub encoding cache in both uncompressed
and zstd modes, partial delivery and reconnect. Small focused properties
use the same components below. This is sampled contract testing, not an
exhaustive proof. Enabled diagnostic properties currently expose known bugs;
a failing aggregate is not a green acceptance suite.

## Reusable components

| Component                                                   | Focused callers                                                                                           | Composed caller and contract                                                                                                                                                                                                                                                                                                          |
| ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `propcheck.World`, `CheckWorld`, `WorldProbes`              | `state.TestWorldMutationProperty`, `TestWorldReferenceOwnership`                                          | `streamPropertySystem.checkWorld` after every write: owned node/user values, sorted membership, user ownership, node-key winners, machine-key buckets, retained old keys and snapshots. Native maps and scans; no graph, State, policy or mapper implementation imports.                                                              |
| `propcheck.DrawPolicy`, `ReorderPolicy`                     | `policy/v2.TestIncrementalPolicyRapidHistory`                                                             | `drawOperation` draws valid ACL/grant/SSH/capability/via policies, duplicates/reorders rules and restores earlier documents. The fleet supplies u1/u2/u3, tag:srv/router, and matching IPv4/IPv6 addresses. Duplicate app grants retain multiplicity. Known policy classifications survive reorder, duplicate and historical restore. |
| `propcheck.ElectRoutes`                                     | State route-election properties                                                                           | `checkWorld` predicts global winners after every write, preserving previous winners. Allow-all wire checks predict AllowedIPs and PrimaryRoutes. `TestRapidStreamRouteFailover` uses the same result for ordinary and tag:a via grants. Rich policy alias resolution remains a separate compiler oracle.                              |
| `propcheck.DrawDNSRecords`, `CanonicalDNSRecords`           | External `types` DNS properties                                                                           | DNS operations and causal checks use the same record domain and normalization. Expected graph records and client records come from input; equivalent canonical records must not publish a revision.                                                                                                                                   |
| `wirePeers`, `wireUpgrade`, `wirePatchable`, `wireSemantic` | `TestRapidWire*`, `TestWireReachableFailures`, `TestPropertyClientContracts`                              | `propertyClient` uses the exact same pinned peer replay, including PeersChanged patchification. LastSeen is ignored only while Online is true. Zero DiscoKey, expiry clears and lost offline fields remain observable.                                                                                                                |
| `propertyClient`                                            | `TestPropertyClientContracts`, `TestRapidStreamModelPatchFields`, operation contracts                     | Tracks self, peers, named packet filters, SSH, DNS, DERP, domain, service collection, sticky profiles and a delta-only removal observer. Unseen owner profiles fail.                                                                                                                                                                  |
| `peerHistoryModel`                                          | `TestHubRapid*`, `TestPeerHistoryModel*`                                                                  | `open`, `update`, deletion and `checkHistory` share attempted/confirmed/retired/reconnect transitions. Simple-policy membership comes from World inputs; rich-policy membership comes from a separate fresh renderer, never the live stream's sent state. Hub class views may contain self; comparisons remove that non-wire member.  |
| `streamOperation`, `drawOperation`, `apply`, `checkCausal`  | `TestRapidStreamOperationContracts` selects endpoint/global, request/refusal and generated-policy subsets | The whole-system driver draws the same structured operations. Parameters are drawn before application. Model transitions, production application, delivery scheduling and checks are separate.                                                                                                                                        |

Graph transactions, persistent maps and concurrency properties remain local to
the graph package. Exporting their private test drivers would not add a shared
contract to this composition. Existing `TestHubCoalescedCommitsConverge`
exercises real graph subscriptions and Hub coalescing; existing
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
  independently. Requests omit Hostinfo and carry one endpoint; richer incoming
  request normalization stays in the existing State tests.
- **Database fixture:** users have explicit IDs and timestamps. Nodes have real
  SQLite rows before request operations and graph publication. The DB clock is
  fixed per fixture. Direct graph edits are deliberately not advertised as
  durable DB writes. Policy changes use in-memory `State.SetPolicy`, not the
  durable policy API.
- **Independent intent:** allow-all, deny-all and self/member policies predict
  peer membership and tag-versus-user ownership from World. Peer keys and tags
  are checked against input. Allow-all maps independently predict addresses,
  subnet winners and approved exit routes. Rich policies use the shared
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
`TestIncrementalDuplicateAppGrantInvalidatesFilter` (stale reduced filter and
missed destination notification). Refactoring must not make these disappear.

## Remaining limits

The fixture is bounded to 3–8 nodes and four capability-version boundaries.
There is no Noise/HTTP transport, real Tailscale process, PostgreSQL, process
restart, registration authorization, certificate issuance, or durable policy
failure/retry path in this driver. Hub TTL, capacity and concurrent session
limits are tested by the focused shared-ledger suite; this composition keeps
one live session per node and a fixed hub clock. Legacy PeerSeenChange,
OnlineChange, legacy DERP strings, unsigned peers and client Debug actions are
outside the generated wire domain. Pinned replay covers the modern fields
Headscale emits. Generated failures can stop a broad history early, so focused
component campaigns remain necessary.
