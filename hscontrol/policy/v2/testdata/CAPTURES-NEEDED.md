# Captures still needed from the hosted Tailscale service

For whoever has `tscap` and a test tailnet on the hosted service. Self-contained: nothing
outside this repository is needed.

**Lifecycle:** write each answer under its scenario here. Delete a scenario once its
capture is in `testdata/` and headscale follows it (golden test passing, `TODO(kradalby)`
for its key gone). **Remove this file from git when the last one is settled.**

## Why

Headscale's policy engine is held to a written reference model by property tests. In 17
places headscale's behaviour differs from the plain reading of the policy, or its intent is
unknown, and no existing capture settles which is right. The maintainer's rule: **headscale
follows the hosted service.** Each scenario below asks one yes/no question of the hosted
service. The answer decides whether headscale is fixed or its behaviour is declared
correct.

## What to deliver

1. One capture file per scenario in the existing format (`hscontrol/types/testcapture`,
   HuJSON, schema version 1), named by the scenario id, in the category directory given.
   Existing examples: `hscontrol/policy/v2/testdata/routes_results/`,
   `…/grant_results/`, `…/issue_3212/`.
2. Under each scenario below, an **Answer:** line: the answer to its question (quote the
   netmap field that shows it), anything unexpected, or "could not be set up" with the
   reason where that is the answer.
3. If the hosted service **refuses** a policy or a setup, record the exact error. A
   refusal is an answer.

Do not adjust a scenario to make it "work" without recording what was changed.

## Conventions

- Base topology: `_topologies/routes.hujson` as used by the `routes-*` scenarios (users
  odin@example.com, thor@example.org, freya@example.com; `tag:router` caterpie 10.0.0.0/8
  and squirtle 10.33.0.0/16; `tag:exit` charmander; `tag:exit`+`tag:router` wartortle
  172.16.0.0/24 and exit; `tag:ha` butterfree/metapod 192.168.1.0/24; `tag:server`,
  `tag:prod`, `tag:client` plain nodes; one untagged node per user). "Add" below means a
  topology variant; keep every other node.
- Policy skeleton (groups, hosts, tagOwners, autoApprovers): the one the `routes-*`
  scenarios share. Only the `acls`/`grants` (and what a scenario names) differ.
- Capture every node's netmap. The fields that carry answers: `PacketFilter` rules
  (`SrcIPs`, `DstPorts`, `IPProto`, `CapGrant`), each peer's presence, `AllowedIPs`,
  `PrimaryRoutes`, `CapMap`, and self `Addresses`.
- 8.8.8.0/24 and 2001:4860::/32 stand for "a public prefix served as a subnet route". They
  are only announced inside the test tailnet.

## Do these two first: they decide whether five others can exist

### P0 `routes-tailnet-range-route` (routes)

- **Question:** can a node advertise, and have approved, a subnet route inside the
  tailnet's own address range?
- **Setup:** add to caterpie the advertised routes `100.64.0.0/30` and the `/32` of the
  untagged odin node's address; approve both (API or auto-approver). Policy: `* -> *:*`.
- **Look at:** does tailscaled accept the advertisement; does the API accept the approval;
  do peers get the route in caterpie's `AllowedIPs`.
- **Meaning:** if the service refuses, the shapes in S5, S6, S8 (and one variant of S1)
  cannot exist there. Record that and skip them: headscale then decides for itself,
  probably by refusing such routes too.

### P1 `nodeattrs-disable-ipv4-star` (nodeattrs)

- **Question:** what addresses does a node hold when IPv4 is turned off for it, and what
  does `*` cover then?
- **Setup:** check `nodeattrs_results/` first for an existing `disable-ipv4` capture; if
  one answers both parts, cite it and skip. Otherwise `nodeAttrs: [{"target":
["tag:server"], "attr": ["disable-ipv4"]}]`, policy `* -> *:*`.
- **Look at:** the tag:server node's self `Addresses` and its `Addresses` as a peer (IPv4
  absent, or present but unused?); `SrcIPs` for `*` in any filter (still the IPv4 range?).
- **Meaning:** tells headscale whether a one-family node is a normal state and confirms
  that `*` is the service's fixed ranges, not the addresses in use.

## Policy readings

Each entry: headscale today / the other reading / what in the capture decides.

### S1 `grant-via-wide-destination` (grant) — `policy/via-own-address`

- **Policy:** grant `{"src": ["autogroup:member"], "dst": ["0.0.0.0/1"], "ip": ["*"],
"via": ["tag:router"]}`.
- **Question:** at via router caterpie (serves 10.0.0.0/8, own address in 100.64.0.0/10,
  both inside 0.0.0.0/1), is the rule's destination written whole or cut to its routes?
- **Headscale:** `DstPorts` holds `0.0.0.0/1` whole, so the client also accepts members
  to caterpie's own address.
- **Other reading:** `DstPorts` holds `10.0.0.0/8` only.
- **Decides:** caterpie's `PacketFilter` `DstPorts` for that rule.

### S2 `routes-star-approved-unannounced` (routes) — `policy/star-approved-routes`

- **Policy:** `* -> *:*`.
- **Setup (steps):** a node advertises 10.99.0.0/24; approve it; the node then stops
  advertising it (`tailscale set --advertise-routes=`). Confirm through the API that the
  route is still enabled but no longer advertised. Capture after that.
- **Question:** do other nodes' filters still list 10.99.0.0/24 among the `SrcIPs` of `*`?
- **Headscale:** yes (every approved route, announced or not).
- **Other reading:** no (only routes being served).

### S3 `routes-internet-public-subnet` (routes) — `policy/internet-at-subnet-routers`

- **Policy:** `{"action": "accept", "src": ["autogroup:member"], "dst":
["autogroup:internet:*"]}`.
- **Setup:** add a plain subnet router (new `tag:pub`, **not** an exit node) advertising
  and approved for 8.8.8.0/24.
- **Questions:** (a) does that router's filter carry a rule from members to 8.8.8.0/24 or
  to the internet ranges? (b) do members see it as a peer with 8.8.8.0/24 in `AllowedIPs`?
- **Headscale:** yes to both (autogroup:internet read as a set of addresses).
- **Other reading:** no to both (the internet only through exit nodes).

### S4 `routes-destination-wider-than-route` (routes) — `policy/unrouted-whole-destination`

- **Policy:** `{"action": "accept", "src": ["autogroup:member"], "dst":
["10.0.0.0/16:*"]}`.
- **Setup:** add a router approved for 10.0.0.0/24 that also advertises 10.0.1.0/24,
  **left unapproved**.
- **Question:** is the rule's destination at that router `10.0.0.0/16` whole, or cut to
  the approved 10.0.0.0/24?
- **Headscale:** whole, so the client also accepts traffic for the unapproved 10.0.1.0/24
  it advertises.
- **Note:** existing `routes-*` captures may already show the whole form for an approved
  narrower route (squirtle 10.33.0.0/16 under `internal` 10.0.0.0/8). If so, cite one and
  only add the unapproved route.

### S5 `grant-via-router-covered` (grant) — `policy/via-router-cover`, `policy/via-peer-shortcut` — needs P0

- **Policy:** grant `{"src": ["odin@example.com"], "dst": ["10.0.0.0/8"], "ip": ["*"],
"via": ["tag:router"]}`.
- **Setup:** caterpie (tag:router, 10.0.0.0/8) also routes `100.64.0.0/30` covering odin's
  node, which makes caterpie a source by route. Add a thor-owned node routing caterpie's
  own `/32`.
- **Question:** are caterpie and that thor node shown each other as peers?
- **Headscale:** yes (the via link names the router's own addresses, and a node routing
  them matches). **Other reading:** no: a via grant links its sources with its routers
  only.

### S6 `acl-self-routed-by-other-user` (acl) — `policy/others-self` — needs P0

- **Policy:** `{"action": "accept", "src": ["autogroup:member"], "dst":
["autogroup:self:*"]}`.
- **Setup:** a thor-owned node routes the `/32` of odin's node.
- **Questions:** (a) does thor's router get odin's self rule in its filter for that
  address? (b) does it see odin's other devices? (c) are odin's devices given the route?
- **Headscale:** no to all (a user's self rules only with that user's device at one end).

### S7 `grant-via-reach` (grant, three captures a/b/c) — `policy/via-reach`

- **a:** grant `{"src": ["odin@example.com"], "dst": ["8.8.8.0/24"], "ip": ["*"], "via":
["tag:exit"]}`. Does exit node charmander get a rule from odin to 8.8.8.0/24, and is
  odin steered to it? Headscale: no rule (via reaches subnet routes only).
- **b:** same with `"dst": ["*"], "via": ["tag:router"]`. What is the destination at
  caterpie: its 10.0.0.0/8, the fixed tailnet ranges, or nothing? Headscale: `*` is the
  tailnet ranges, so caterpie gets nothing.
- **c:** same with `"dst": ["*"], "via": ["tag:exit"]`. Does charmander get a rule, and
  to what? Headscale: nothing.

### S8 `grant-via-self` (grant) — `policy/via-self` — effect needs P0

- **Policy:** grant `{"src": ["odin@example.com"], "dst": ["autogroup:self"], "ip": ["*"],
"via": ["tag:router"]}`.
- **Questions:** (a) does the service accept the policy at all? (b) with caterpie routing
  odin's node's `/32`, does caterpie get a rule?
- **Headscale:** accepts the policy, gives no rule.

### S9 `grant-app-wildcard-destination` (grant) — `policy/app-wildcard`

- **Policy:** grant `{"src": ["autogroup:member"], "dst": ["*"], "app":
{"example.com/cap/x": [{}]}}`.
- **Questions:** (a) do members get caterpie's 10.0.0.0/8 in its `AllowedIPs` (as the
  existing via golden v84 shows for an app grant to the subnet itself)? (b) is exit node
  charmander shown the members as peers? (c) what `Dsts` does each `CapGrant` carry?
- **Headscale:** no to (a) and (b): `*` as an app destination is the tailnet ranges.

### S10 `grant-via-internet-one-family-exit` (grant) — `policy/via-exit-internet`

- **Policy:** grant `{"src": ["odin@example.com"], "dst": ["autogroup:internet"], "ip":
["*"], "via": ["tag:exit"]}`.
- **Setup:** a tag:exit node approved for `0.0.0.0/0` **only** (not `::/0`) that also
  serves the subnet 2001:4860::/32.
- **Question:** what does its filter accept from odin: the IPv4 internet only, or the
  IPv6 internet ranges too (in whole or as 2001:4860::/32)?
- **Headscale:** the whole internet in both families is written, and the client keeps
  what any of its routes overlap, so 2001:4860::/32 is accepted.

### S11 `grant-via-public-prefix-exit-routes` (grant) — `policy/via-router-exit-routes`

- **Policy:** grant `{"src": ["*"], "dst": ["8.8.8.0/24"], "ip": ["*"], "via":
["tag:router"]}`.
- **Setup:** a tag:router node serving 8.8.8.0/24. charmander stays a tag:exit exit node.
- **Question:** is the tag:router node given charmander's `0.0.0.0/0` and `::/0` in
  `AllowedIPs`? Compare a plain source (an untagged node).
- **Headscale:** the router gets them, the plain source does not.

### S12 `grant-via-internet-exit-is-source` (grant) — `policy/via-exit-source-routes`

- **Policy:** grant `{"src": ["autogroup:member", "autogroup:tagged"], "dst":
["autogroup:internet"], "ip": ["udp:*"], "via": ["tag:exit"]}`.
- **Setup:** add an untagged node (owner odin) approved for the subnet 8.8.8.0/24.
  charmander is the tag:exit exit node and, being tagged, a source.
- **Questions:** in charmander's netmap, (a) does the 8.8.8.0/24 router's `AllowedIPs`
  hold 8.8.8.0/24? (b) does any exit node without `tag:exit` hold exit routes?
- **Headscale:** (a) yes, though that router accepts nothing from charmander; (b) no.

### S13 `grant-app-destination-repeated` (grant) — `policy/app-values-repeated`

- **Policy:** grant `{"src": ["autogroup:member"], "dst": ["*", "*"], "app":
{"example.com/cap/x": [{"v": 1}]}}`.
- **Question:** is it accepted, and does a receiver's filter carry the capability once or
  twice (count `CapGrant` entries and values)?
- **Headscale:** twice. Cosmetic.

## Behaviour questions (not single-shot policy captures)

These need steps (`Capture.Steps`) or the admin API. If `tscap` cannot drive one, say so
in its answer; the default named below then stands.

### B1 `users-tagowner-domain-wildcard` — `policy/owner-wildcard-user-half`

- **Policy:** `tagOwners: {"tag:x": ["user:*@example.com"]}`.
- **Questions:** (a) is the policy accepted? (b) can odin@example.com bring a device up
  with `--advertise-tags=tag:x` by interactive login? (c) can an auth key carrying `tag:x`
  be created as odin? (d) the same three as thor@example.org (must be refused).
- **Headscale:** accepts the policy; existing devices of the domain's users count as
  owners, a login or key requesting the tag is refused.
- **Default if not answerable:** honour the wildcard on every path.

### B2 `auth-key-relogin-after-tag` — `ClaimableBy` in `hscontrol/types/node.go`

- **Steps**, device list (id, node key, machine key, tags, user) from the API after each:
  1. A machine joins with odin's **reusable** auth key (no tags).
  2. An admin sets `tag:server` on it through the API.
  3. The user logs in again interactively on that machine, keeping the tags.
  4. The same machine logs in with the same auth key again, forcing re-authentication (a
     new node key).
- **Question:** after step 4, how many devices exist for that machine, and which holds
  the tags?
- **Headscale:** two: the tagged node stays, and a new node owned by odin is created.
- **Default if not answerable:** keep and document.

### B3 `map-empty-endpoints` — `state/map-request-keeps-endpoints`

- **Question:** when a connected client reports an empty endpoint list after a non-empty
  one, does a peer's view of its `Endpoints` empty?
- **How:** a real tailscaled rarely reports none. This probably needs a hand-built map
  request (control client library with a fixed endpoint list: first two endpoints, then
  none) while a second node's netmap is watched.
- **Headscale:** the peer keeps the old endpoints.
- **Default if not answerable:** keep and document.

## Already settled (no capture needed)

- `policy/exit-destination-routes`: capture
  `issue_3212/routes-b18-autogroup-internet-wildcard-src-with-exit-autoapprover` shows the
  service gives an exit node the subnet routes behind an internet rule's sources.
  Headscale will be fixed to match.
- Nodes sharing an address, nodes without any address, nodes outside the service's
  ranges: cannot exist on the hosted service. Decided without captures.

## Where each answer lands in headscale

Reference clauses and their pins: `hscontrol/policy/policymodel/reference.go` (the
`Contested` constants; each doc comment names its production site and tests). Keys are
greppable as `TODO(kradalby): <key>`. A capture that agrees with headscale turns the
clause into the reference's plain reading; one that disagrees becomes a failing golden
test first, then the fix.

Every finding here exists on `main` as well as on the policy-graph branch (the old compile
in `policy/v2/compiled.go` there), so each answer is acted on in both.
