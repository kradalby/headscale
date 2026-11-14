# Debugging and troubleshooting

Headscale and Tailscale provide debug and introspection capabilities that can be helpful when things don't work as
expected. This page explains some debugging techniques to help pinpoint problems.

Please also have a look at [Tailscale's Troubleshooting guide](https://tailscale.com/docs/reference/troubleshooting). It
offers a many tips and suggestions to troubleshoot common issues.

## Tailscale

The Tailscale client itself offers many commands to introspect its state as well as the state of the network:

- [Check local network conditions](https://tailscale.com/docs/reference/tailscale-cli#netcheck): `tailscale netcheck`
- [Get the client status](https://tailscale.com/docs/reference/tailscale-cli#status): `tailscale status --json`
- [Get DNS status](https://tailscale.com/docs/reference/tailscale-cli#dns): `tailscale dns status --all`
- Client logs: `tailscale debug daemon-logs`
- Client netmap: `tailscale debug netmap`
- Test DERP connection: `tailscale debug derp headscale`
- And many more, see: `tailscale debug --help`

Many of the commands are helpful when trying to understand differences between Headscale and Tailscale SaaS.

## Headscale

### Application logging

The log levels `debug` and `trace` can be useful to get more information from Headscale.

```yaml hl_lines="3"
log:
  # Valid log levels: panic, fatal, error, warn, info, debug, trace
  level: debug
```

### Database logging

The database debug mode logs all database queries. Enable it to see how Headscale interacts with its database. This also
requires the application log level to be set to either `debug` or `trace`.

```yaml hl_lines="3 7"
database:
  # Enable debug mode. This setting requires the log.level to be set to "debug" or "trace".
  debug: false

log:
  # Valid log levels: panic, fatal, error, warn, info, debug, trace
  level: debug
```

### Metrics and debug endpoint

Headscale provides a metrics and debug endpoint. It allows to introspect different aspects such as:

- Information about the Go runtime, memory usage and statistics
- Connected nodes and pending registrations
- Active policy, filters and SSH policy
- Current DERPMap
- Prometheus metrics

!!! warning "Keep the metrics and debug endpoint private"

    The listen address and port can be configured with the `metrics_listen_addr` variable in the [configuration
    file](configuration.md). By default it listens on localhost, port 9090.

    Keep the metrics and debug endpoint private to your internal network and don't expose it to the Internet.

    The metrics and debug interface can be disabled completely by setting `metrics_listen_addr: null` in the
    [configuration file](configuration.md).

Query metrics via <http://localhost:9090/metrics> and get an overview of available debug information via
<http://localhost:9090/debug/>. Metrics may be queried from outside localhost but the debug interface is subject to
additional protection despite listening on all interfaces.

The debug interface accepts requests addressed to an IP literal, `localhost`, the host in `server_url`, or the hostname
in `metrics_listen_addr`. Hostnames are case-insensitive and may end in a dot. Other hostnames receive HTTP 403; use an
IP address or one of the accepted names. `dns.base_domain` does not add accepted hosts. This check covers all debug
paths, including statsviz. `/metrics` accepts any Host.

=== "Direct access"

    Access the debug interface directly on the server where Headscale is installed.

    ```console
    curl http://localhost:9090/debug/
    ```

=== "SSH port forwarding"

    Use SSH port forwarding to forward Headscale's metrics and debug port to your device.

    ```console
    ssh <HEADSCALE_SERVER> -L 9090:localhost:9090
    ```

    Access the debug interface on your device by opening <http://localhost:9090/debug/> in your web browser.

=== "Via debug key"

    The access control of the debug interface supports the use of a debug key. Traffic is accepted if the path to a
    debug key is set via the environment variable `TS_DEBUG_KEY_PATH` and the debug key sent as value for `debugkey`
    parameter with each request.

    ```console
    openssl rand -hex 32 | tee debugkey.txt
    export TS_DEBUG_KEY_PATH=debugkey.txt
    headscale serve
    ```

    Access the debug interface on your device by opening `http://<IP_OF_HEADSCALE>:9090/debug/?debugkey=<DEBUG_KEY>` in
    your web browser. The `debugkey` parameter must be sent with every request.

=== "Via debug IP address"

    The debug endpoint expects traffic from localhost. A different debug IP address may be configured by setting the
    `TS_ALLOW_DEBUG_IP` environment variable before starting Headscale. The debug IP address is ignored when the HTTP
    header `X-Forwarded-For` is present.

    ```console
    export TS_ALLOW_DEBUG_IP=192.168.0.10       # IP address of your device
    headscale serve
    ```

    Access the debug interface on your device by opening `http://<IP_OF_HEADSCALE>:9090/debug/` in your web browser.

### Graph explorer

Debug builds serve a graph explorer at `/debug/graph/` on the metrics and debug listener. It draws the control plane's
cells, devices, users, tags, routes, DERP regions and extra DNS records as one snapshot shows them, and can follow
changes live. Only the flake's `headscale-debug` package includes it:

```console
nix build .#headscale-debug
./result/bin/headscale serve
```

Release binaries, container images, `go build` and the default `nix build` omit it: `/debug/graph/` answers 404, the
`/debug/` index does not link it and the rest of the debug interface is unchanged.

The explorer shows the policy source, every device's packet filter and SSH policy, so it has the gate of `/debug/policy`,
`/debug/filter` and `/debug/ssh`: loopback, Tailscale addresses, `TS_ALLOW_DEBUG_IP` or the debug key. Unlike
`/debug/statsviz/` it does not admit other private-network addresses. The page carries the `debugkey` parameter to its
own assets and requests and sends no `Referer`. Data requests a browser marks as cross-site are refused, as are those
from browsers that mark no site but name another host as their origin.

Bounds and cost:

- A scene holds at most 200 objects and 1000 relationships; search or focus to see others. Search and focus are
  limited to 512 bytes each and responses to 2 MiB; a larger scene or detail returns an error.
- Every scene scans all devices. A live viewer repeats that up to four times a second while anything changes, even
  outside its scene, so the cost grows with tailnet size times live viewers. Prefer paused snapshots on large
  tailnets.
- At most four live viewers are connected at once; another live connection is refused with 503 until one closes. A
  hidden browser tab closes its live connection and reloads the scene when shown again. A live connection ends after
  a minute and the browser reconnects for a new baseline, so a viewer that vanished without closing its connection
  holds its place for at most that long.
- Details are answered for the last eight scenes sent to any viewer. Older revisions answer 409 and the page asks for
  a refresh. The retained snapshots share unchanged state with the current one.

### Checking control-plane progress

These signals describe different stages of an update:

| Signal                                                             | What it establishes                                                                                                                                                                                                                                                   | What it does not establish                                                          |
| ------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `/health` on the main HTTP listener                                | The database ping succeeded (`pass`, HTTP 200), or failed (`fail`, HTTP 500).                                                                                                                                                                                         | Graph progress, policy correctness, or client delivery.                             |
| `headscale_world_commits_total`                                    | A graph transaction published a new snapshot after the initial snapshot. Node, user, policy, extra DNS record and DERP changes count; a node batch counts once, unless its commit panics and the surviving writes are retried individually, each counting separately. | Database persistence, a response for every commit, or client receipt.               |
| `/debug/batcher`                                                   | Map sessions currently registered with the mapper hub, including the number per node.                                                                                                                                                                                 | A session consuming notifications, completing writes, or applying a new netmap.     |
| `/debug/nodestore`, `/debug/filter`, `/debug/ssh`, `/debug/routes` | Current in-memory nodes, compiled policy output and route assignments.                                                                                                                                                                                                | A client's installed state, or a consistent snapshot across separate HTTP requests. |
| `/debug/derp`                                                      | A summary of the current graph's DERP regions and servers.                                                                                                                                                                                                            | A historical DERP map, its revision, or client receipt.                             |

The commit counter excludes transactions that stage no edit — an unknown node, unchanged users, a byte-identical policy, equal DNS records or DERP maps — and refused and panicking transactions. A panicking node batch is retried write by write and each surviving publication counts separately. A node write that stages an identical copy of the node still counts. A separate startup DNS or DERP publication
counts; constructing the initial graph snapshot does not. A committed node or user change still counts if its policy
recompile fails and the graph retains the last good compiled policy. `headscale_world_commit_panics_total` reports
panicking node write batches. `headscale_world_write_batch_size` records completed node batches, including no-op
batches; failed batches are not observed, but successful individual retries are.

Notifications coalesce: a slow stream can render the latest snapshot without sending every intermediate commit.
An idle commit counter is normal when nothing changes. A rising counter or a connected session alone cannot prove
that a particular update reached a client.

When an update appears stuck:

1. Check `/health` and server logs for database errors, `node write panicked`, or
   `compiling policy; keeping the last good policy`.
1. Inspect the affected node and live policy/route output using the debug endpoints above. `/debug/policy` reads the
   configured policy file or database document; it does not prove that document is the one currently compiled —
   `/debug/policy-manager` reports the policy manager state, the policy currently serving.
   `/debug/config` exposes DNS configuration; there is no dedicated DNS revision or history endpoint.
1. Check `/debug/batcher` for the node's session, then inspect its `tailscale debug netmap`, `tailscale status --json`
   or `tailscale dns status --all` to verify the relevant state arrived. Compare the actual field, such as the endpoint,
   route or extra DNS record, rather than inferring delivery from the connection count.

With `HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH` set before server startup, `/debug/mapresponses` exposes dumped responses.
These are generated responses, dumped before network writes; they do not prove receipt or application by a client.

### Revalidating policy and auditing incremental compilation

Installing byte-identical policy through the in-memory `SetPolicy` operation or a file reload skips policy compilation
and its `tests`/`sshTests`, even when users or nodes changed since the policy was accepted. Durable policy API updates
always validate against the current users and nodes before storing the policy, including byte-identical source. A
successful identical API update preserves the graph revision and does not wake map streams.
SIGHUP does not auto-approve routes; route auto-approval runs when route announcements change.
To run both test blocks against the running server's current users and nodes without changing its policy:

```console
headscale policy check --file policy.json
```

When the server is stopped, add `--bypass-server-and-access-database-directly` to check against persisted users and nodes.
At boot, failing stored policy tests log a warning and do not prevent startup.

`HEADSCALE_DEBUG_POLICY_AUDIT=1` compares incremental policy compilation and derived peer classes with fresh compilation
and peer scans when those graph cells recompute. Mismatches log `policy audit`; integration tests treat them as failures.
This checks policy-derived results, including filters, route matchers and peer visibility. It does not continuously
revalidate policy tests, audit endpoint-only commits that skip recompilation, or check DNS rendering, notification
routing, response diffs, network writes or client state. Fresh peer scans are quadratic, so this diagnostic can add
substantial cost on large tailnets.

### Offline peer-history memory

The map-session hub keeps peer IDs across disconnects so a reconnect can announce
peers removed while a client was away. Clients before capability version 148 —
the version Tailscale v1.104, the first release whose clients also derive
removals from a full netmap (tailscale/tailscale#15660), reports — need explicit
`PeersRemoved` responses for consumers that only process peer deltas. A full map
alone does not clear those consumers' old peers.

Clients sent the same snapshot's peer view share its backing array, and a
rebuild hands a class whose view did not change the previous generation's
array, as long as it keeps a member whose previous class saw the same peers;
a rebuild that keeps no such member shares a fresh array. Sharing ends where
a class's view changes: with one new node joining, receiving its map and
disconnecting at each generation, `H` offline nodes retain `H` arrays even
when the current policy has only one peer class. Starting with three nodes,
those arrays contain `H × (H + 7) / 2` IDs, so unbounded history would grow
quadratically with tailnet growth; current class count alone is not a memory
bound.

History is therefore bounded once a node's last session ends, as upstream bounded
its per-node sent-peer state:

- it is dropped 15 minutes after the node's last session left, checked when a
  node connects or disconnects and every 5 minutes;
- history beyond what connected nodes are being sent costs at most 524,288 (2¹⁹)
  units: one per offline node, the peer-ID arrays its history pins (a view shared
  by several nodes counted once), and the union of the failed writes of a
  connected node whose writes keep failing. Past that, the nodes that left first
  lose their history first, then the node whose history just grew.

A node back after its history was dropped gets the full map alone, the map a new
session gets. Clients at capability version 148 or later derive every removal from
it. A pre-148 consumer that only processes peer deltas keeps peers deleted while it
was away; that is the cost of the bound, which upstream paid after its 15 minutes
too. A node back in time keeps its history and is sent its removals. A connected
node's history is otherwise the view it is being sent. Deleted peers can remain in
a surviving node's history until its reconnect or the bound drops it.

Reproduce the retained storage measurement from the repository's Nix shell:

```console
go test ./hscontrol/mapper -run '^$' -bench '^BenchmarkOfflinePeerHistory$' -benchtime=1x -count=1
```

The benchmark drives real map-stream objects, simulates successful delivery with
`Delivered`, and removes every session with `Leave`. It performs no transport
writes and advances no clock, so only the ID bound applies. `shared` disconnects
all clients from one snapshot; `growing` disconnects one per membership
generation. `growing-sparse` keeps the growing counts while spacing the new node
IDs by 2²⁰: a control for ID-compressed designs, which raw ID slices ignore, and
where spacing would start paying for tree nodes. The hub never gates history on
the capability a client reports, so no capability version avoids it.

Every count the benchmark emits is a metric of the run you just made, so read
them from your own output rather than from a table: counts such as
`retained-IDs` follow from the shape alone, but `history-ID-bytes` includes slice
capacity, which depends on the Go toolchain's allocator and growth policy.
What scales with what:

- `shared`: one view serves every offline node, so `view-IDs` and
  `history-arrays` stay constant while `histories` grows with the offline node
  count. Storage grows roughly with the current class size plus one slice
  header per node.
- `growing`: each offline node holds its own generation, so `retained-IDs`
  grows quadratically with the offline node count until the ID bound drops the
  oldest histories. Past the bound, `retained-IDs` stays below it while
  `histories` and `history-arrays` fall short of the offline node count.
- `growing-sparse` reports the same counts as `growing`; compare it against
  `growing` only to see what an ID-compressed design would change.

Every simulated delivery succeeds, so the counts cover confirmed views; a write
that fails part way keeps the same arrays as unconfirmed attempts, and they count
against the same bound. Bytes exclude map entries, slice headers, render caches
and allocator overhead; they are not total process heap. Elapsed time covers the
session lifecycle (joining, rendering and the delivery bookkeeping the hub
records) and excludes store membership writes, so it is not an isolated
history-update latency measurement. To size a deployment, run the benchmark at
the node counts you expect and compare `retained-IDs` against the bound above.

History is in memory and does not survive a server restart: a peer deleted while a
pre-148 client was offline across a restart is never announced as removed, and the
full map it reconnects with does not clear those consumers' stale peers.

Compact persistent sets could share unchanged portions of historical generations,
and so keep more history under the same bound, but need a connection between class
generations and shared construction to avoid rebuilding a set per session. Dense
ID chunks help sequential IDs; sparse views can spend more space on tree nodes
than the current ID slices. Retention based on client capability would also need
proof across failed writes, overlapping sessions, upgrades and downgrades; the
capability of the last connection alone does not establish what a future client
retains.
