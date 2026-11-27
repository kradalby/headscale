package integration

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/juanfont/headscale/integration/tsric"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// TestTailscaleRustAxum tests that the tailscale-rs axum example can join a
// headscale network and serve HTTP to other peers on the tailnet.
//
// Architecture:
//
//	headscale (control) <--- tsic (probe client) --curl--> tsric (axum server)
//
// The test:
//  1. Creates a headscale environment with one regular Tailscale client (tsic)
//  2. Creates a tailscale-rs container running the axum example (tsric)
//  3. Verifies the tsric node registers with headscale
//  4. Uses the tsic client to curl the axum web server through the tailnet
func TestTailscaleRustAxum(t *testing.T) {
	IntegrationSkip(t)

	// Set up a scenario with one user and one regular Tailscale client.
	// The regular client acts as a "probe" to verify the tsric node
	// is reachable on the tailnet.
	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"}, //nolint:goconst // consistent with other integration tests
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tailscalers"),
		// The embedded DERP server uses a self-signed cert that
		// tailscale-rs cannot validate without a custom CA bundle, so
		// we route DERP through Tailscale's public relays.
		hsic.WithPublicDERP(),
		// TODO: drop WithoutTLS once tailscale-rs lets us inject the
		// headscale CA into its trust chain; until then the control
		// plane has to be plain HTTP for the Rust client to register.
		hsic.WithoutTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	// Get the headscale instance and probe client
	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 1, "expected exactly 1 probe client")

	probeClient := allClients[0]

	// Create auth key for the tailscale-rs node
	users, err := headscale.ListUsers()
	require.NoError(t, err)
	require.NotEmpty(t, users, "expected at least one user")

	var userID uint64

	for _, u := range users {
		if u.Name == "user1" { //nolint:goconst
			userID = mustParseID(u.Id)

			break
		}
	}

	require.NotZero(t, userID, "user1 not found")

	pak, err := headscale.CreateAuthKey(userID, false, true)
	require.NoError(t, err)

	// Determine the network and headscale connection details
	networks := scenario.Networks()
	require.NotEmpty(t, networks)

	network := networks[0]
	headscaleIP := headscale.GetIPInNetwork(network)
	headscaleHostname := headscale.GetHostname()
	headscaleEndpoint := headscale.GetEndpoint()

	t.Logf("Headscale endpoint: %s (hostname: %s, IP: %s)",
		headscaleEndpoint, headscaleHostname, headscaleIP)

	// Create the tailscale-rs container
	tsrsOpts := []tsric.Option{
		tsric.WithNetwork(network),
		tsric.WithHeadscaleURL(headscaleEndpoint),
		tsric.WithAuthKey(pak.Key),
		tsric.WithExtraHosts([]string{headscaleHostname + ":" + headscaleIP}),
	}

	cert := headscale.GetCert()
	if len(cert) > 0 {
		tsrsOpts = append(tsrsOpts, tsric.WithCACert(cert))
	}

	t.Log("Creating tailscale-rs container (first build may take several minutes)...")

	tsrs, err := tsric.New(scenario.Pool(), tsrsOpts...)
	require.NoError(t, err, "failed to create tailscale-rs container")

	defer func() {
		_, _, err := tsrs.Shutdown()
		if err != nil {
			t.Logf("error shutting down tailscale-rs container: %s", err)
		}
	}()

	// Wait for the tailscale-rs node to appear in headscale's node list.
	// Verify it gets both IPv4 and IPv6 addresses and has the expected hostname.
	var (
		rustNodeIPv4 string
		rustNodeIPv6 string
		rustNodeName string
	)

	t.Log("Waiting for tailscale-rs node to register with headscale...")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)

		// Expect 2 nodes: 1 tsic probe + 1 tsric
		assert.GreaterOrEqual(c, len(nodes), 2,
			"expected at least 2 nodes (1 probe + 1 tailscale-rs)")

		// Find the tailscale-rs node by hostname prefix
		for _, n := range nodes {
			if strings.HasPrefix(n.GivenName, "tsrs-") {
				addrs := n.IpAddresses
				if len(addrs) > 0 {
					rustNodeIPv4 = addrs[0]
				}

				if len(addrs) > 1 {
					rustNodeIPv6 = addrs[1]
				}

				rustNodeName = n.GivenName
			}
		}

		assert.NotEmpty(c, rustNodeIPv4, "tailscale-rs node should have an IPv4 address")
	}, 120*time.Second, 2*time.Second, "tailscale-rs node should register with headscale")

	require.NotEmpty(t, rustNodeIPv4, "failed to find tailscale-rs node IP")

	t.Logf("tailscale-rs node %q registered with IPv4=%s IPv6=%s",
		rustNodeName, rustNodeIPv4, rustNodeIPv6)

	// Verify IPv6 was allocated. The axum example only listens on IPv4,
	// so we can't curl via IPv6, but headscale should still assign both.
	assert.NotEmpty(t, rustNodeIPv6,
		"headscale should assign both IPv4 and IPv6 to the tailscale-rs node")

	// Verify the hostname propagated correctly from the config
	assert.True(t, strings.HasPrefix(rustNodeName, "tsrs-"),
		"tailscale-rs node name should start with tsrs- prefix")

	// Verify the probe client sees the tailscale-rs node as a peer
	t.Log("Verifying probe client sees tailscale-rs as a peer...")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status := assertClientStatus(c, probeClient)
		if status == nil {
			return
		}

		found := false

		for _, peerKey := range status.Peers() {
			peer := status.Peer[peerKey]
			if strings.HasPrefix(peer.HostName, "tsrs-") {
				found = true
			}
		}

		assert.True(c, found, "probe client should see tsrs node as a peer")
	}, 30*time.Second, 2*time.Second, "probe should see tailscale-rs peer in status")

	// Test 1: GET /index.html — verify the axum web server serves content
	axumURL := fmt.Sprintf("http://%s/index.html", rustNodeIPv4)

	t.Logf("Verifying axum web server is reachable at %s via probe client...", axumURL)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := probeClient.Curl(axumURL)
		assert.NoError(c, err, "curl to axum server failed")
		assert.Contains(c, result, "tailscale-rs",
			"expected index.html to contain 'tailscale-rs'")
	}, 120*time.Second, 2*time.Second, "axum /index.html should be reachable from probe client")

	t.Log("axum web server is serving content through the tailnet")

	// Test 2: GET /assets/index.css — verify static asset serving works
	cssURL := fmt.Sprintf("http://%s/assets/index.css", rustNodeIPv4)

	t.Logf("Verifying static asset at %s...", cssURL)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := probeClient.Curl(cssURL)
		assert.NoError(c, err, "curl to CSS asset failed")
		assert.Contains(c, result, "font-family",
			"expected CSS file to contain 'font-family'")
	}, 10*time.Second, 1*time.Second, "axum should serve static CSS assets")

	// Test 3: Sequential POST /count — verify the counter increments correctly.
	// This exercises multiple TCP connections and proves the netstack maintains
	// state across requests.
	countURL := fmt.Sprintf("http://%s/count", rustNodeIPv4)

	t.Logf("Verifying /count POST endpoint increments at %s...", countURL)

	// First POST establishes connectivity and gets the initial counter value
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		stdout, _, err := probeClient.Execute([]string{
			"curl", "--silent",
			"--connect-timeout", "3",
			"--max-time", "5",
			"-X", "POST",
			countURL,
		})
		assert.NoError(c, err, "curl POST to /count failed")
		assert.Contains(c, stdout, `"count"`,
			"expected /count response to contain 'count'")
	}, 30*time.Second, 2*time.Second, "axum /count POST should work")

	// Fire several more POSTs and verify the counter advances.
	// The axum handler returns {"count": N} where N is the pre-increment value.
	// After the initial [assert.EventuallyWithT] loop we don't know the exact counter,
	// but two back-to-back POSTs should return consecutive values.
	t.Log("Verifying counter increments across multiple requests...")

	var firstCount, secondCount string

	stdout1, _, err := probeClient.Execute([]string{
		"curl", "--silent", "--max-time", "5", "-X", "POST", countURL,
	})
	require.NoError(t, err, "first sequential POST failed")

	firstCount = stdout1

	stdout2, _, err := probeClient.Execute([]string{
		"curl", "--silent", "--max-time", "5", "-X", "POST", countURL,
	})
	require.NoError(t, err, "second sequential POST failed")

	secondCount = stdout2

	t.Logf("Counter responses: first=%s second=%s", firstCount, secondCount)

	// Verify they're different (counter is incrementing)
	require.NotEqual(t, firstCount, secondCount,
		"counter should increment between sequential POST requests")

	t.Log("TestTailscaleRustAxum: all checks passed")
}

// TestTailscaleRustCapabilitySources is the canary of the client fallback
// (TODO(capsrc/client)): with capability sources on and a rule whose source
// is an identity selector, the tailscale-rs node, which looks no capability
// up, must be sent the source as addresses and so still admit traffic,
// while the official client beside it is sent the capability.
func TestTailscaleRustCapabilitySources(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{NodesPerUser: 1, Users: []string{"user1"}})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tsrscapsrc"),
		hsic.WithACLPolicy(&policyv2.Policy{ACLs: []policyv2.ACL{{
			Action:       "accept",
			Sources:      []policyv2.Alias{usernamep("user1@")},
			Destinations: []policyv2.AliasWithPorts{aliasWithPorts(usernamep("user1@"), tailcfg.PortRangeAny)},
		}}}),
		hsic.WithCapabilitySources(),
		// As in TestTailscaleRustAxum: tailscale-rs trusts neither the
		// embedded DERP's certificate nor headscale's.
		hsic.WithPublicDERP(),
		hsic.WithoutTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 1)

	probe := allClients[0]

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := probe.Netmap()
		if !assert.NoError(c, err) {
			return
		}

		assert.True(c, slices.ContainsFunc(nm.PacketFilterRules.AsSlice(), func(r tailcfg.FilterRule) bool {
			return slices.ContainsFunc(r.SrcIPs, func(s string) bool { return strings.HasPrefix(s, "cap:") })
		}), "the official client is sent a capability source")
	}, 30*time.Second, time.Second, "capability sources are on")

	users, err := headscale.ListUsers()
	require.NoError(t, err)

	var userID uint64

	for _, u := range users {
		if u.Name == "user1" {
			userID = mustParseID(u.Id)
		}
	}

	require.NotZero(t, userID)

	pak, err := headscale.CreateAuthKey(userID, false, true)
	require.NoError(t, err)

	network := scenario.Networks()[0]

	tsrs, err := tsric.New(scenario.Pool(),
		tsric.WithNetwork(network),
		tsric.WithHeadscaleURL(headscale.GetEndpoint()),
		tsric.WithAuthKey(pak.Key),
		tsric.WithExtraHosts([]string{headscale.GetHostname() + ":" + headscale.GetIPInNetwork(network)}),
	)
	require.NoError(t, err)

	defer func() {
		_, _, err := tsrs.Shutdown()
		if err != nil {
			t.Logf("shutting down tailscale-rs: %s", err)
		}
	}()

	var rustIPv4 string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)

		for _, n := range nodes {
			if strings.HasPrefix(n.GivenName, "tsrs-") && len(n.IpAddresses) > 0 {
				rustIPv4 = n.IpAddresses[0]
			}
		}

		assert.NotEmpty(c, rustIPv4, "tailscale-rs registers")
	}, 120*time.Second, 2*time.Second)

	require.NotEmpty(t, rustIPv4)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := probe.Curl(fmt.Sprintf("http://%s/index.html", rustIPv4))
		assert.NoError(c, err)
		assert.Contains(c, result, "tailscale-rs")
	}, 120*time.Second, 2*time.Second, "tailscale-rs admits the user1@ source sent to it as addresses")
}

// TestTailscaleRustFilterChunks is the canary of the delivery fallback
// (TODO(capsrc/chunk-client)): with named chunks on, the tailscale-rs node,
// which keeps chunks for its runtime's life rather than per map session,
// must be sent its whole filter under "base" and so follow every policy
// edit, while the official client beside it is sent chunks. It checks the
// fallback is in force through traffic; the tailscale-rs behaviour it rests
// on is read from its source, not driven here.
func TestTailscaleRustFilterChunks(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario(ScenarioSpec{NodesPerUser: 1, Users: []string{"user1"}})
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	allow := func(port uint16) *policyv2.Policy {
		return &policyv2.Policy{ACLs: []policyv2.ACL{{
			Action:       "accept",
			Sources:      []policyv2.Alias{usernamep("user1@")},
			Destinations: []policyv2.AliasWithPorts{aliasWithPorts(usernamep("user1@"), tailcfg.PortRange{First: port, Last: port})},
		}}}
	}

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tsrschunks"),
		hsic.WithACLPolicy(allow(80)),
		hsic.WithFilterChunks(),
		// As in TestTailscaleRustAxum: tailscale-rs trusts neither the
		// embedded DERP's certificate nor headscale's.
		hsic.WithPublicDERP(),
		hsic.WithoutTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 1)

	probe := allClients[0]

	users, err := headscale.ListUsers()
	require.NoError(t, err)

	var userID uint64

	for _, u := range users {
		if u.Name == "user1" {
			userID = mustParseID(u.Id)
		}
	}

	require.NotZero(t, userID)

	pak, err := headscale.CreateAuthKey(userID, false, true)
	require.NoError(t, err)

	network := scenario.Networks()[0]

	tsrs, err := tsric.New(scenario.Pool(),
		tsric.WithNetwork(network),
		tsric.WithHeadscaleURL(headscale.GetEndpoint()),
		tsric.WithAuthKey(pak.Key),
		tsric.WithExtraHosts([]string{headscale.GetHostname() + ":" + headscale.GetIPInNetwork(network)}),
	)
	require.NoError(t, err)

	defer func() {
		_, _, err := tsrs.Shutdown()
		if err != nil {
			t.Logf("shutting down tailscale-rs: %s", err)
		}
	}()

	var rustIPv4 string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)

		for _, n := range nodes {
			if strings.HasPrefix(n.GivenName, "tsrs-") && len(n.IpAddresses) > 0 {
				rustIPv4 = n.IpAddresses[0]
			}
		}

		assert.NotEmpty(c, rustIPv4, "tailscale-rs registers")
	}, 120*time.Second, 2*time.Second)

	require.NotEmpty(t, rustIPv4)

	reaches := func(want bool, why string) {
		t.Helper()

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			result, err := probe.Curl(fmt.Sprintf("http://%s/index.html", rustIPv4))
			if want {
				assert.NoError(c, err)
				assert.Contains(c, result, "tailscale-rs")
			} else {
				assert.Error(c, err)
			}
		}, 120*time.Second, 2*time.Second, why)
	}

	reaches(true, "tailscale-rs admits port 80")

	// Each edit replaces the rule: a client holding chunks it should no
	// longer hold would keep admitting port 80.
	for _, step := range []struct {
		port uint16
		want bool
		why  string
	}{
		{81, false, "port 80 revoked"},
		{80, true, "port 80 granted again"},
		{81, false, "port 80 revoked again"},
	} {
		err := headscale.SetPolicy(allow(step.port))
		require.NoError(t, err)

		reaches(step.want, step.why)
	}
}
