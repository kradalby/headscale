# Registration methods

Headscale supports multiple ways to register a node. The preferred registration method depends on the identity of a node
and your use case.

## Identity model

Tailscale's identity model distinguishes between personal and tagged nodes:

- A personal node (or user-owned node) is owned by a human and typically refers to end-user devices such as laptops,
  workstations or mobile phones. End-user devices are managed by a single user.
- A tagged node (or service-based node or non-human node) provides services to the network. Common examples include web-
  and database servers. Those nodes are typically managed by a team of users. Some additional restrictions apply for
  tagged nodes, e.g. a tagged node is not allowed to [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh)
  into a personal node.

Headscale implements Tailscale's identity model and distinguishes between personal and tagged nodes where a personal
node is owned by a Headscale user and a tagged node is owned by a tag. Tagged devices are grouped under the special user
`tagged-devices`.

## Registration methods

There are two main ways to register new nodes, [web authentication](#web-authentication) and [registration with a pre
authenticated key](#pre-authenticated-key). Both methods can be used to register personal and tagged nodes.

### Web authentication

Web authentication is the default method to register a new node. It's interactive, where the client initiates the
registration and the Headscale administrator needs to approve the new node before it is allowed to join the network. A
node can be approved with:

- Headscale CLI (described in this documentation)
- [Headscale API](api.md)
- Or delegated to an identity provider via [OpenID Connect](oidc.md)

Pending interactive registrations retain client Hostinfo until approval or expiry. Headscale rejects Hostinfo larger
than 16 KiB after JSON encoding, including when refreshing a followup registration. The Noise registration endpoint
returns HTTP 200 with the error in `RegisterResponse.Error`, without admitting a cache entry. The auth cache also
limits the number of pending entries. These limits do not represent an exact heap-memory bound. Authkey
registrations do not enter the pending-entry cache: they present a valid credential before any Hostinfo is
retained, so the cap applies to the interactive paths only.

Web authentication relies on the presence of a Headscale user. Use the `headscale users` command to create a new
user[^1]:

```console
headscale users create <USER>
```

=== "Personal devices"

    Run `tailscale up` to login your personal device:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL>
    ```

    Usually, a browser window with further instructions is opened. This page explains how to complete the registration
    on your Headscale server and it also prints the Auth ID required to approve the node:

    ```console
    headscale auth register --user <USER> --auth-id <AUTH_ID>
    ```

    Congrations, the registration of your personal node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `<USER>` as the owner of the node.

=== "Tagged devices"

    Your Headscale user needs to be authorized to register tagged devices. This authorization is specified in the
    [`tagOwners`](https://tailscale.com/docs/reference/syntax/policy-file#tag-owners) section of the
    [policy](policy.md). A simple example looks like this:

    ```json title="The user alice can register nodes tagged with tag:server"
    {
      "tagOwners": {
        "tag:server": ["alice@"]
      },
      // more rules
    }
    ```

    Run `tailscale up` and provide at least one tag to login a tagged device:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --advertise-tags tag:<TAG>
    ```

    Usually, a browser window with further instructions is opened. This page explains how to complete the registration
    on your Headscale server and it also prints the Auth ID required to approve the node:

    ```console
    headscale auth register --user <USER> --auth-id <AUTH_ID>
    ```

    Headscale checks that `<USER>` is allowed to register a node with the specified tag(s) and then transfers ownership
    of the new node to the special user `tagged-devices`. The registration of a tagged node is complete and it should be
    listed as "online" in the output of `headscale nodes list`. The "User" column displays `tagged-devices` as the owner
    of the node. See the "Tags" column for the list of assigned tags.

### Pending authentication limits

Headscale keeps admitted authentication requests until they complete or expire.
When registration capacity is reached, new requests receive HTTP 503 with
`Retry-After` instead of invalidating someone else's pending approval. Existing
approvals and pre-authenticated key registration remain available. SSH checks
have 64 reserved entries beyond the registration allocation, including in the
OIDC state cache.

The default registration allocation is 1024 entries. The advanced
`tuning.register_cache_max_entries` setting changes that allocation. Pending
registration retains only hostname, OS and requested tags from Hostinfo; other
metadata arrives with the node's first MapRequest. The full cached registration
must fit within 64 KiB when serialized; larger payloads are rejected without
truncating authentication metadata. Noise
registrations return HTTP 200 with `RegisterResponse.Error` so the Tailscale
client displays the permanent size error. The admin API reports this size error
as HTTP 413.
At the default allocation, retained registration payloads use at most 64 MiB
plus record overhead. This is a cache-storage bound, not a bound on total server
memory or concurrent request processing.

OIDC login URLs must reference an existing pending authentication of the matching
type. OIDC callback state is single-use, including when the identity provider
exchange fails; restart the browser login flow after such an error. Capacity
limits protect admitted requests but cannot guarantee admission during sustained
overload.

### Pre authenticated key

Registration with a pre authenticated key (or auth key) is a non-interactive way to register a new node. The Headscale
administrator creates a preauthkey upfront and this preauthkey can then be used to register a node non-interactively.
Its best suited for automation.

An unexpired node can restart with its unchanged node key and its previously used, expired or revoked auth key, provided
it does not change ownership or tags. A different auth key must be valid, including when changing ephemeral lifetime.
This compatibility path preserves the existing node expiry; extending or removing
expiry requires a valid auth key. An expired node, including an admin-expired tagged node, requires fresh authorization.
A logout or registration update that still resolves to its node after a reauthentication replaced the node key is
rejected instead of modifying the newer registration: the logout reaches the client as an error in
`RegisterResponse.Error`, a non-streaming map request as HTTP 404. A logout whose node key no longer resolves at all
starts a fresh interactive registration and gets a new `AuthURL`.

=== "Personal devices"

    A personal node is always assigned to a Headscale user. Use the `headscale users` command to create a new user[^1]:

    ```console
    headscale users create <USER>
    ```

    Create a new pre authenticated key for your user, by name or by the `<USER_ID>` that `headscale user list` shows:

    ```console
    headscale preauthkeys create --user <USER>
    ```

    The above prints a pre authenticated key with the default settings (can be used once and is valid for one hour). Use
    this auth key to register a node non-interactively:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
    ```

    Congrations, the registration of your personal node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `<USER>` as the owner of the node.

=== "Tagged devices"

    Create a new pre authenticated key and provide at least one tag:

    ```console
    headscale preauthkeys create --tags tag:<TAG>
    ```

    The above prints a pre authenticated key with the default settings (can be used once and is valid for one hour). Use
    this auth key to register a node non-interactively. You don't need to provide the `--advertise-tags` parameter as
    the tags are automatically read from the pre authenticated key. Advertising a subset of the key's tags is accepted;
    any other tag is rejected:

    ```console
    tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
    ```

    The registration of a tagged node is complete and it should be listed as "online" in the output of
    `headscale nodes list`. The "User" column displays `tagged-devices` as the owner of the node. See the "Tags" column for the list of
    assigned tags.

[^1]: [Ensure that the Headscale username does not end with `@`.](oidc.md#reference-a-user-in-the-policy)
