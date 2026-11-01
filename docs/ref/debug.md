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

Setting or reloading the byte-identical live policy is a no-op for policy compilation and its `tests`/`sshTests`.
This remains true when users or nodes changed since the policy was accepted. SIGHUP can still run route auto-approval.
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
