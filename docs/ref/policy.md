# Policy

Headscale implements a large portion of Tailscale's [policy
features](https://tailscale.com/docs/features/tailnet-policy-file), most notably access control based on
[ACLs](https://tailscale.com/docs/features/access-control/acls) and
[Grants](https://tailscale.com/docs/features/access-control/grants) or [Tailscale
SSH](https://tailscale.com/docs/features/tailscale-ssh). See [limitations](#limitations) to learn about missing features
and notable implementation differences between Headscale and Tailscale.

Headscale uses the same [huJSON](https://github.com/tailscale/hujson) based file format as Tailscale. By default, no
policy is loaded which means that Headscale allows all traffic between nodes. To start using a policy file[^1], specify
its path in the `policy.path` key in the [configuration file](configuration.md).

Headscale needs to be reloaded to pick up changes to the policy file. Either reload Headscale via its systemd service
(`sudo systemctl reload headscale`) or by sending a SIGHUP signal (`sudo kill -HUP $(pidof headscale)`) to the main
process. Headscale logs the result of policy processing after each reload.

Please have a look at Tailscale's policy related documentation to learn more:

- [Tailscale policy file](https://tailscale.com/docs/features/tailnet-policy-file): A description of supported sections
  within the policy file along with links to syntax references for each section.
- [ACLs](https://tailscale.com/docs/features/access-control/acls): How to configure access control using ACLs.
- [Grants](https://tailscale.com/docs/features/access-control/grants): Introduction to Grants with links to [syntax
  reference](https://tailscale.com/docs/reference/syntax/grants),
  [examples](https://tailscale.com/docs/reference/examples/grants) and a [migration guide from ACLs to
  Grants](https://tailscale.com/docs/reference/migrate-acls-grants).

## Getting started

Headscale supports both [ACLs](https://tailscale.com/docs/features/access-control/acls) and
[Grants](https://tailscale.com/docs/features/access-control/grants) to write an access control policy. We recommend the
use of Grants since ACLs are considered legacy and will not receive new features by Tailscale.

### Allow All

If you define a policy file but completely omit the `"acls"` or `"grants"` section, Headscale will default to an [allow
all](https://tailscale.com/docs/reference/examples/acls#allow-all-default-acl) policy. This means all devices connected
to your tailnet will be able to communicate freely with each other.

```json title="policy.json"
{}
```

### Deny All

To [prevent all communication within your tailnet](https://tailscale.com/docs/reference/examples/acls#deny-all), you can
include an empty array for the `"grants"` section in your policy file.

```json title="policy.json"
{
  "grants": []
}
```

### More examples

- See our documentation on [subnet routers](routes.md#subnet-router) and [exit nodes](routes.md#exit-node) to learn how
  to restrict their use or how to automatically approve them.
- The Tailscale documentation provides a large collection of configuration examples:
    - [ACL examples](https://tailscale.com/docs/reference/examples/acls)
    - [Grants examples](https://tailscale.com/docs/reference/examples/grants)
    - [SSH configuration](https://tailscale.com/docs/features/tailscale-ssh#configure-tailscale-ssh)
    - [Define a tag](https://tailscale.com/docs/features/tags#define-a-tag)

______________________________________________________________________

## Limitations

- [Device postures](https://tailscale.com/docs/features/device-posture) and the related sections such as `postures` or
  `srcPosture` aren't supported.
- [IP sets](https://tailscale.com/docs/features/tailnet-policy-file/ip-sets) aren't supported.
- A subset of [Autogroups](#autogroups) are available.
- With [capability sources](#capability-sources) (the default), peers can read which source groups, tags and users a
  node belongs to, and a node that starts announcing routes briefly accepts more ICMP than its policy allows. See [What
  peers can read](#what-peers-can-read) and [ICMP window](#icmp-window-when-a-node-starts-announcing-routes).

## Refused policies

Headscale refuses some policies Tailscale's hosted service refuses too. A refused policy is never served:

- a policy that is stored when Headscale starts, in `policy.mode: file` and `database` alike, stops startup, with the
  validation error in the log. Correct the document, then start Headscale again; in database mode, the
  [FAQ's recovery steps](../about/faq.md#my-policy-is-stored-in-the-database-and-headscale-refuses-to-start-due-to-an-invalid-policy-how-can-i-recover)
  store a corrected policy while the server will not start;
- a reload that reads one, by SIGHUP in either mode, logs the error and keeps the policy in force, and the API and
  `headscale policy set` refuse to store one, so the running policy never changes to a refused document.

The refusals, each with the error Headscale logs:

- `user:*@domain` names every user of an email domain, and only as a source or destination of a rule. As a tag owner
  it is refused with `only tag:name, group:name, role autogroups, or user@domain are allowed`, as a group member with
  `invalid group member type`: list the users.
- A grant with `via` steers traffic through the nodes carrying its tags. Its `dst` accepts only prefixes, hosts and
  `autogroup:internet`; anything else is refused with `cannot use via with non-IP dsts`. A prefix that overlaps the
  Tailscale address ranges, except the 4via6 range, is refused with `cannot use via with tailscale IPs`. Write the
  prefix the router serves, or `autogroup:internet`.

## Autogroups

Headscale supports several [Autogroups](https://tailscale.com/docs/reference/targets-and-selectors#autogroups) that
automatically include users, destinations, or devices with specific properties. Autogroups provide a convenient way to
write policy rules without manually listing individual users or devices.

### [`autogroup:internet`](https://tailscale.com/docs/reference/targets-and-selectors#autogroupinternet)

Allows access to the internet through [exit nodes](routes.md#exit-node). Can only be used in policy destinations.

```json title="policy.json"
{
  "grants": [
    {
      "src": ["alice@"],
      "dst": ["autogroup:internet"],
      "ip": ["*"]
    }
  ]
}
```

### [`autogroup:member`](https://tailscale.com/docs/reference/targets-and-selectors#autogrouprole)

Includes all [personal (untagged) devices](registration.md/#identity-model).

```json title="policy.json"
{
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["tag:prod-app-servers"],
      "ip": ["80,443"]
    }
  ]
}
```

### [`autogroup:tagged`](https://tailscale.com/docs/reference/targets-and-selectors#autogrouptagged)

Includes all devices that [have at least one tag](registration.md/#identity-model).

```json title="policy.json"
{
  "grants": [
    {
      "src": ["autogroup:tagged"],
      "dst": ["tag:monitoring"],
      "ip": ["9090"]
    }
  ]
}
```

### [`autogroup:self`](https://tailscale.com/docs/reference/targets-and-selectors#autogroupself)

Includes devices where the same user is authenticated on both the source and destination. Does not include tagged
devices. Can only be used in policy destinations.

```json title="policy.json"
{
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["autogroup:self"],
      "ip": ["*"]
    }
  ]
}
```

!!! warning "The current implementation of `autogroup:self` is inefficient"

    Using `autogroup:self` may cause performance degradation on the Headscale coordinator server in large deployments,
    as filter rules must be compiled per-node rather than globally and the current implementation is not very efficient.

    If you experience performance issues, consider using more specific policy rules or limiting the use of
    `autogroup:self`.

    ```json title="policy.json"
    {
      "grants": [
        // The following rules allow internal users to communicate with their
        // own nodes in case autogroup:self is causing performance issues.
        {
          "src": ["boss@"],
          "dst": ["boss@"],
          "ip": ["*"]
        },
        {
          "src": ["dev1@"],
          "dst": ["dev1@"],
          "ip": ["*"]
        },
        {
          "src": ["intern1@"],
          "dst": ["intern1@"],
          "ip": ["*"]
        }
      ]
    }
    ```

### [`autogroup:nonroot`](https://tailscale.com/docs/reference/targets-and-selectors#other-built-in-targets)

Used in Tailscale SSH rules to allow access to any user except root. Can only be used in the `users` field of SSH rules.

```json title="policy.json"
{
  "ssh": [
    {
      "action": "accept",
      "src": ["autogroup:member"],
      "dst": ["autogroup:self"],
      "users": ["autogroup:nonroot"]
    }
  ]
}
```

### [`autogroup:danger-all`](https://tailscale.com/docs/reference/targets-and-selectors#autogroupdanger-all)

This autogroup resolves to all IP addresses (`0.0.0.0/0` and `::/0`) which also includes all IP addresses outside the
standard Tailscale IP ranges. This autogroup can only be used as source.

## Node Attributes

[Node attributes](https://tailscale.com/docs/reference/syntax/policy-file#node-attributes) allow for device-specific
configuration and attributes. At least the following node attributes are currently supported by Headscale[^2]:

- `drive:access`, `drive:share`: [Taildrive support](https://tailscale.com/docs/features/taildrive).
- `suggest-exit-node`, `suggest-exit-node-ui`: [Automatic exit node selection](routes.md#automatic-exit-node-selection).
- `nextdns:<profile>`, `nextdns:no-device-info`: [NextDNS integration](https://tailscale.com/docs/integrations/nextdns).
  Be sure to set NextDNS as global resolver in the [configuration](configuration.md).
- `magicdns-aaaa`: Respond to AAAA queries on the local [MagicDNS](https://tailscale.com/docs/features/magicdns)
  resolver at 100.100.100.100.
- `disable-ipv4`: Selectively disable IPv4 for specific nodes. This may be useful to work around [CGNat
  conflicts](https://tailscale.com/docs/reference/troubleshooting/network-configuration/cgnat-conflicts).
- `randomize-client-port`: Allocate a [random port for WireGuard
  traffic](https://tailscale.com/docs/reference/syntax/policy-file#randomizeclientport) instead of the static default
  port 41641.
- `disable-captive-portal-detection`: [Disable automatic captive portal
  detection](https://tailscale.com/docs/integrations/captive-portals#disable-captive-portal-detection).
- `ssh-behavior-v1`: Run Tailscale SSH sessions on a Linux node without `su`, PAM or a login environment, so `ssh -tt`
  keeps job control but `~/.profile` is not read. Tailscale's own control plane sets it on every node; Headscale leaves
  it off.

```json title="policy.json"
{
  "nodeAttrs": [
    {
      // Enable MagicDNS AAAA records for all nodes
      "target": ["*"]
      "attr": ["magicdns-aaaa"]
    }
  ]
}
```

## Network-wide policy options

The following options are applied for the entire tailnet. Consider [node attributes](#node-attributes) for a more
fine-grained configuration instead.

- `randomizeClientPort`: Allocate a [random port for WireGuard
  traffic](https://tailscale.com/docs/reference/syntax/policy-file#randomizeclientport) instead of the static default
  port 41641.

```json title="policy.json"
{
  // Use a random WireGuard port for the entire tailnet
  "randomizeClientPort": true
}
```

- `derpMap`: Add custom DERP regions or remove regions from the DERP map, like a
  [Tailscale policy file](https://tailscale.com/docs/reference/derp-servers/custom-derp-servers). See
  [DERP](derp.md#customize-the-derp-map-in-the-policy) for the rules.

```json title="policy.json"
{
  // Do not use the New York DERP region
  "derpMap": {
    "Regions": {
      "1": null
    }
  }
}
```

## How filters reach clients

Headscale compiles the policy into a packet filter for every node, which the node's client enforces on traffic it
receives. Two options decide how that filter is written and sent. Both are on by default, independent of each other and
read at startup only: [`policy.capability_sources`](configuration-options.md#policy.capability_sources) and
[`policy.filter_chunks`](configuration-options.md#policy.filter_chunks).

### Capability sources

With `policy.capability_sources`, a rule's identity sources are not written as the addresses of their members but as a
capability: users (`alice@`), `user:*@domain`, groups, tags, `autogroup:member` and `autogroup:tagged` become
`cap:https://headscale.net/cap/src/<selector>`, for example `cap:https://headscale.net/cap/src/group:eng`. An
`autogroup:self` rule names the owner: `cap:https://headscale.net/cap/src/owner:<user ID>`. Headscale sends every node,
to its peers and to itself, with a `CapMap` entry for each such selector it belongs to that some rule names as a source.
The client accepts a packet when the node holding the source address carries the capability.

Membership then travels with the peers, not the filters. A node joining, leaving or being retagged changes the peers
other nodes are sent, and their entries, but not the packet filter of a node sent capabilities. A group edit changes the
entries of the moved users' nodes, for every node that sees them.

```json title="policy.json"
{
  "groups": {
    "group:eng": ["alice@"]
  },
  "tagOwners": {
    "tag:web": ["alice@"]
  },
  "grants": [
    {
      "src": ["group:eng"],
      "dst": ["tag:web"],
      "ip": ["tcp:443"]
    }
  ]
}
```

Take `web1`, tagged `tag:web`, and Alice's laptop at `100.64.0.1` and `fd7a:115c:a1e0::1`:

=== "Capability sources (default)"

    `web1`'s filter names the group:

    ```json
    {
      "SrcIPs": ["cap:https://headscale.net/cap/src/group:eng"],
      "DstPorts": [
        // web1's addresses, port 443
      ],
      "IPProto": [6]
    }
    ```

    `web1` is sent the laptop with `"https://headscale.net/cap/src/group:eng": null` in its `CapMap`, and so is the
    laptop itself. Adding `bob@` to `group:eng` adds the entry to Bob's nodes; `web1`'s filter stays as it is.

=== "Address sources"

    `web1`'s filter lists the members' addresses:

    ```json
    {
      "SrcIPs": ["100.64.0.1", "fd7a:115c:a1e0::1"],
      "DstPorts": [
        // web1's addresses, port 443
      ],
      "IPProto": [6]
    }
    ```

    No node carries an entry. Adding `bob@` to `group:eng` adds the addresses of Bob's nodes to `web1`'s filter.

#### Where addresses stay

Headscale sends a source as addresses wherever the client cannot match it as a capability:

- Sources that are addresses by nature: `*`, hosts, prefixes, `autogroup:internet` and `autogroup:danger-all`.
- Every rule sent to a node whose local networks exceed its own addresses: a node that announces subnet or exit routes,
  approved or not, an app connector, or a node hosting a service IP. See [ICMP
  window](#icmp-window-when-a-node-starts-announcing-routes).
- Every rule sent to a node whose client is not known to apply capability sources. Only Tailscale's own client, built
  with Go, at or above the minimum version Headscale supports, is sent capabilities; any other, tailscale-rs among
  them, is sent addresses.
- A rule granting app capabilities (`app` in a grant, such as `tailscale.com/cap/drive`): the client grants them by
  address only.
- A rule naming a protocol other than TCP, UDP, SCTP and ICMP: the client matches those by address only.

Apart from the first, these follow the client's current behaviour and are tracked to be lifted
([tailscale/tailscale#12542](https://github.com/tailscale/tailscale/issues/12542)). `/debug/capability-sources` counts
the nodes and rules each reason applies to, see [Debugging](debug.md#capability-sources-and-filter-delivery).

#### What peers can read

Every node that sees a node is sent its entries. Any node can therefore read, for itself and for every peer it sees,
which source selectors that node belongs to: the groups, tags, users, `user:*@domain` domains and autogroups the policy
names as sources, and its owner's user ID where an `autogroup:self` rule applies. `tailscale debug netmap` shows them,
group names and membership included. Use [address sources](#turn-capability-sources-off) to keep membership off the
wire.

#### ICMP window when a node starts announcing routes

On ICMP, the Tailscale client accepts a capability source without checking the rule's destinations, which is why nodes
that announce routes are sent addresses. A node that starts announcing routes, or becomes an app connector, still holds
its capability filter until it installs the address filter the new announcement earns. Until then it accepts ICMP
(every type except echo replies and errors, which it accepts from anyone anyway) from any holder of any capability its
filter names, to any address of its new local networks: for an exit node, every address it forwards to.

This normally lasts one map request round trip. It has no bound while the control server is unreachable, or when
Headscale refuses the map request carrying the announcement, for example with HTTP 413 for a Hostinfo over its size
limits. TCP, UDP and SCTP are not affected, as the client checks their destinations. Withdrawing routes opens no window.
Tracked as [tailscale/tailscale#12542](https://github.com/tailscale/tailscale/issues/12542). If this is not acceptable,
[turn capability sources off](#turn-capability-sources-off).

#### Turn capability sources off

Address sources send every source as addresses and no source capabilities in `CapMap`, as earlier releases did:

```yaml title="config.yaml"
policy:
  capability_sources: false
```

In either mode, capabilities under `https://headscale.net/cap/src/` are reserved: a policy naming one in `nodeAttrs` or
an app grant is refused, and a stored one stops Headscale at startup.

### Filter chunks

With `policy.filter_chunks`, a node's filter goes to its client as named chunks in the map response's `PacketFilters`:
one chunk per rule (`r/<hash>`), and every rule granting app capabilities together in one chunk (`c/<hash>`), sent whole
again when any of them changes, since applications read their values in order. A later response carries only the
chunks the client does not hold and `null` for those that went; an unchanged filter sends nothing. Only Tailscale's own
client is sent chunks, by the same test as above; any other, tailscale-rs among them, is sent the whole filter under
`"base"`, as every client is with the option off. Chunks save bytes on the wire; the client still parses its whole
filter again on any change.

With either option on or off, the first response of every map stream carries `"*": null`, which clears every chunk the
client holds, so both options can be turned on or off between restarts.

[^1]: Headscale also allows to store the policy in the database. This is typically only required in case a [web
    interface](integration/web-ui.md) is used.

[^2]: Other key-only node attributes can be used as well. Find them in the client source code with `grep -E ' Cap ' tailcfg/nodecap/nodecap.go` or by using [GitHub code search (requires
    login)](https://github.com/search?q=repo%3Atailscale%2Ftailscale+language%3Ago+path%3Atailcfg%2Fnodecap%2Fnodecap.go+%2F+Cap+%2F&type=code).
