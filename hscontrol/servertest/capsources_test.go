package servertest_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsnet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

const (
	capEng = "https://headscale.net/cap/src/group:eng"
	capDev = "https://headscale.net/cap/src/tag:dev"
)

// capSourcesPolicy lets group:eng and tag:dev reach tag:web on 443.
const capSourcesPolicy = `{
	"groups": {"group:eng": ["alice@"]},
	"tagOwners": {"tag:web": ["ops@"], "tag:dev": ["ops@"], "tag:idle": ["ops@"]},
	"grants": [{"src": ["group:eng", "tag:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]}]
}`

// clientFilter is the packet filter a client holding nm installs: its rules,
// its capability lookup over its own netmap, and its local nets (its
// addresses and the routes it announces).
func clientFilter(t *testing.T, nm *netmap.NetworkMap) *filter.Filter {
	t.Helper()

	var b netipx.IPSetBuilder

	for _, p := range nm.SelfNode.Addresses().All() {
		b.AddPrefix(p)
	}

	for _, p := range nm.SelfNode.Hostinfo().RoutableIPs().All() {
		b.AddPrefix(p)
	}

	local, err := b.IPSet()
	require.NoError(t, err)

	return filter.New(nm.PacketFilter, servertest.CapLookup(nm), local, nil, nil, logger.Discard)
}

// admits reports whether the client holding nm accepts a TCP SYN from src
// to its own IPv4 address on port.
func admits(t *testing.T, nm *netmap.NetworkMap, src netip.Addr, port uint16) bool {
	t.Helper()

	return clientFilter(t, nm).Check(src, nm.SelfNode.Addresses().At(0).Addr(), port, ipproto.TCP) == filter.Accept
}

func ipv4Of(t *testing.T, c *servertest.TestClient) netip.Addr {
	t.Helper()

	nm := c.Netmap()
	require.NotNil(t, nm)

	return nm.SelfNode.Addresses().At(0).Addr()
}

func peerNamed(nm *netmap.NetworkMap, name string) (tailcfg.NodeView, bool) {
	for _, p := range nm.Peers {
		if strings.HasPrefix(p.Name(), name+".") || p.Hostinfo().Hostname() == name {
			return p, true
		}
	}

	return tailcfg.NodeView{}, false
}

func capRuleSources(nm *netmap.NetworkMap) []string {
	var out []string

	for _, r := range nm.PacketFilterRules.All() {
		out = append(out, r.SrcIPs...)
	}

	slices.Sort(out)

	return out
}

func setCapPolicy(t *testing.T, srv *servertest.TestServer, pol string) {
	t.Helper()

	changed, err := srv.State().SetPolicy([]byte(pol))
	require.NoError(t, err)

	if changed {
		require.NoError(t, srv.State().ReloadPolicy())
	}
}

// TestCapabilitySourcesThroughClient is check C: real control clients in
// capability mode. The receiving client's netmap carries the stamps, the
// filter it builds from what it holds admits and refuses the right peers,
// a tag removal and a user change revoke access on the client's own state,
// a node that starts announcing a route flips to addresses and back, and
// after it all the session holds what a fresh one is sent.
func TestCapabilitySourcesThroughClient(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithCapabilitySources())
	setCapPolicy(t, srv, capSourcesPolicy)

	ops := srv.CreateUser(t, "ops")
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")

	web := servertest.NewClient(t, srv, "web", servertest.WithUser(ops), servertest.WithTags("tag:web"))
	a := servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice))
	b := servertest.NewClient(t, srv, "bob-laptop", servertest.WithUser(bob))
	dev := servertest.NewClient(t, srv, "dev", servertest.WithUser(ops), servertest.WithTags("tag:dev"))

	aIP, bIP, devIP := ipv4Of(t, a), ipv4Of(t, b), ipv4Of(t, dev)

	web.WaitForCondition(t, "capability sources and stamped peers", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		ap, okA := peerNamed(nm, "alice-laptop")
		dp, okD := peerNamed(nm, "dev")

		return okA && okD && ap.HasCap(capEng) && dp.HasCap(capDev) &&
			slices.Equal(capRuleSources(nm), []string{"cap:" + capEng, "cap:" + capDev})
	})

	nm := web.Netmap()
	require.True(t, admits(t, nm, aIP, 443), "group:eng's member connects")
	require.True(t, admits(t, nm, devIP, 443), "tag:dev's member connects")
	require.False(t, admits(t, nm, bIP, 443), "bob is in neither")
	require.False(t, admits(t, nm, aIP, 80), "only 443")

	a.WaitForCondition(t, "self stamped", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return nm.SelfNode.HasCap(capEng)
	})

	rules := nm.PacketFilterRules.AsSlice()

	// A tag removal revokes on the client: the peer's stamp goes, the
	// filter stays.
	devID := findNodeID(t, srv, "dev")
	_, err := srv.State().SetNodeTags(devID, []string{"tag:idle"})
	require.NoError(t, err)

	web.WaitForCondition(t, "dev's stamp revoked", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		dp, ok := peerNamed(nm, "dev")

		return !ok || !dp.HasCap(capDev)
	})

	nm = web.Netmap()
	require.False(t, admits(t, nm, devIP, 443), "dev, retagged, is refused")
	require.True(t, admits(t, nm, aIP, 443))
	require.Equal(t, rules, nm.PacketFilterRules.AsSlice(), "the filter names the selector, not its members")

	// A user change revokes: alice@ names nobody once alice is renamed.
	_, err = srv.State().RenameUser(types.UserID(alice.ID), "alice-renamed")
	require.NoError(t, err)

	web.WaitForCondition(t, "alice's stamp revoked", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		ap, ok := peerNamed(nm, "alice-laptop")

		return !ok || !ap.HasCap(capEng)
	})

	require.False(t, admits(t, web.Netmap(), aIP, 443), "alice, no longer in group:eng, is refused")

	_, err = srv.State().RenameUser(types.UserID(alice.ID), "alice")
	require.NoError(t, err)
	_, err = srv.State().SetNodeTags(devID, []string{"tag:dev"})
	require.NoError(t, err)

	web.WaitForCondition(t, "both stamped again", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		ap, okA := peerNamed(nm, "alice-laptop")
		dp, okD := peerNamed(nm, "dev")

		return okA && okD && ap.HasCap(capEng) && dp.HasCap(capDev)
	})

	// Announcing a route widens what the client handles: its filter goes
	// as addresses until it stops.
	announce := func(routes ...netip.Prefix) {
		web.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-web", Hostname: "web", RoutableIPs: routes, GoVersion: "go1.27.3", IPNVersion: "1.94.1",
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		require.NoError(t, web.Direct().SendUpdate(ctx))
	}

	announce(netip.MustParsePrefix("10.9.0.0/24"))

	web.WaitForCondition(t, "address form while announcing", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		srcs := capRuleSources(nm)

		return slices.Contains(srcs, aIP.String()) && slices.Contains(srcs, devIP.String()) &&
			!slices.ContainsFunc(srcs, func(s string) bool { return strings.HasPrefix(s, "cap:") })
	})

	nm = web.Netmap()
	require.True(t, admits(t, nm, aIP, 443))
	require.False(t, admits(t, nm, bIP, 443))

	announce()

	web.WaitForCondition(t, "capability form again", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return slices.Equal(capRuleSources(nm), []string{"cap:" + capEng, "cap:" + capDev})
	})

	webID := findNodeID(t, srv, "web")
	require.Equal(t, "equal", freshNetmapDifference(srv, webID, web.Netmap()), "the session holds what a fresh one is sent")
}

// TestCapabilitySourcesUnknownClient pins the client fallback: a node
// whose client does not report itself as Tailscale's is sent addresses,
// and its peers are stamped all the same.
func TestCapabilitySourcesUnknownClient(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithCapabilitySources())
	setCapPolicy(t, srv, capSourcesPolicy)

	ops := srv.CreateUser(t, "ops")
	alice := srv.CreateUser(t, "alice")

	web := servertest.NewClient(t, srv, "web", servertest.WithUser(ops), servertest.WithTags("tag:web"), servertest.WithUnknownClient())
	a := servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice))

	aIP := ipv4Of(t, a)

	web.WaitForCondition(t, "address sources", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		ap, ok := peerNamed(nm, "alice-laptop")

		return ok && ap.HasCap(capEng) && slices.Contains(capRuleSources(nm), aIP.String())
	})

	nm := web.Netmap()
	require.False(t, slices.ContainsFunc(capRuleSources(nm), func(s string) bool { return strings.HasPrefix(s, "cap:") }),
		"no capability source for an unknown client")

	// The same filter with no capability lookup, as tailscale-rs runs it.
	var b netipx.IPSetBuilder
	for _, p := range nm.SelfNode.Addresses().All() {
		b.AddPrefix(p)
	}

	local, err := b.IPSet()
	require.NoError(t, err)

	f := filter.New(nm.PacketFilter, nil, local, nil, nil, logger.Discard)
	require.Equal(t, filter.Accept, f.Check(aIP, nm.SelfNode.Addresses().At(0).Addr(), 443, ipproto.TCP))

	_ = nodecap.Cap("")
}

// TestCapabilitySourcesThroughLocalBackend drives a real tsnet node, whose
// LocalBackend applies each map response (full netmaps and deltas) to its
// node backend and installs the packet filter its engine checks packets
// with. After each step of a script that moves the filter, a peer's stamps,
// the receiver's own form and the peer set, the engine's filter must admit
// exactly the peers the policy grants.
func TestCapabilitySourcesThroughLocalBackend(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithCapabilitySources(), servertest.WithRealListener())
	st := srv.State()

	setCapPolicy(t, srv, `{
		"groups": {"group:eng": ["alice@", "carol@"]},
		"tagOwners": {"tag:web": ["ops@"], "tag:dev": ["ops@"], "tag:idle": ["ops@"]},
		"grants": [
			{"src": ["group:eng", "tag:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]},
			{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:22"]}
		]
	}`)

	ops := srv.CreateUser(t, "ops")
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")
	carol := srv.CreateUser(t, "carol")

	key, err := st.CreatePreAuthKey(nil, false, false, nil, []string{"tag:web"})
	require.NoError(t, err)

	web := &tsnet.Server{Dir: t.TempDir(), Hostname: "web", ControlURL: srv.URL, AuthKey: key.Key, Logf: logger.Discard}
	t.Cleanup(func() { web.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, err = web.Up(ctx)
	require.NoError(t, err)

	lc, err := web.LocalClient()
	require.NoError(t, err)

	webIP, _ := web.TailscaleIPs()
	webID := findNodeID(t, srv, "web")

	a := servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice))
	b := servertest.NewClient(t, srv, "bob-laptop", servertest.WithUser(bob))
	c := servertest.NewClient(t, srv, "carol-laptop", servertest.WithUser(carol))
	dev := servertest.NewClient(t, srv, "dev", servertest.WithUser(ops), servertest.WithTags("tag:dev"))

	peers := map[string]netip.Addr{"alice": ipv4Of(t, a), "bob": ipv4Of(t, b), "carol": ipv4Of(t, c), "dev": ipv4Of(t, dev)}

	// netmapOf is the netmap web's LocalBackend holds, peers and filter as
	// its deltas left them.
	netmapOf := func(t *testing.T) *netmap.NetworkMap {
		t.Helper()

		v, err := lc.DebugResultJSON(t.Context(), "current-netmap")
		require.NoError(t, err)

		raw, err := json.Marshal(v)
		require.NoError(t, err)

		var nm netmap.NetworkMap
		require.NoError(t, json.Unmarshal(raw, &nm))

		return &nm
	}

	rulesOf := func(t *testing.T) []string {
		t.Helper()

		return capRuleSources(netmapOf(t))
	}

	// Everyone stays web's peer through the wildcard on 22, so revoking
	// 443 moves a stamp rather than the peer set; capability form names no
	// peer's address.
	named := func(srcs []string) bool {
		for _, ip := range peers {
			if slices.Contains(srcs, ip.String()) {
				return true
			}
		}

		return false
	}
	capForm := func(srcs []string) bool {
		return slices.ContainsFunc(srcs, func(s string) bool { return strings.HasPrefix(s, "cap:") }) && !named(srcs)
	}

	// expect waits for web's engine to admit exactly the given peers, each
	// on port, once form holds of the sources web holds.
	expect := func(step string, form func([]string) bool, port uint16, admitted ...string) {
		t.Helper()

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			assert.True(ct, form(rulesOf(t)), "%s: filter form", step)

			f := web.Sys().Engine.Get().GetFilter()

			for name, ip := range peers {
				for _, p := range []uint16{port, 80} {
					want := p == port && slices.Contains(admitted, name)
					assert.Equal(ct, want, f.Check(ip, webIP, p, ipproto.TCP) == filter.Accept, "%s: %s to port %d", step, name, p)
				}
			}
		}, 20*time.Second, 50*time.Millisecond)
	}

	expect("join", capForm, 443, "alice", "carol", "dev")

	// Announcing a route flips web to addresses and back; who it admits
	// stays.
	announce := func(routes ...netip.Prefix) {
		_, err := lc.EditPrefs(t.Context(), &ipn.MaskedPrefs{AdvertiseRoutes: routes, AdvertiseRoutesSet: true})
		require.NoError(t, err)
	}

	announce(netip.MustParsePrefix("10.9.0.0/24"))
	expect("announcing", named, 443, "alice", "carol", "dev")

	announce()
	expect("announcing no more", capForm, 443, "alice", "carol", "dev")

	// A retag revokes through dev's stamp.
	_, err = st.SetNodeTags(findNodeID(t, srv, "dev"), []string{"tag:idle"})
	require.NoError(t, err)
	expect("dev retagged", capForm, 443, "alice", "carol")

	// A policy edit leaving alice out of group:eng revokes through her
	// stamp alone: the rule still names group:eng, which carol holds.
	setCapPolicy(t, srv, `{
		"groups": {"group:eng": ["carol@"]},
		"tagOwners": {"tag:web": ["ops@"], "tag:dev": ["ops@"], "tag:idle": ["ops@"]},
		"grants": [
			{"src": ["group:eng", "tag:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]},
			{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:22"]}
		]
	}`)
	expect("alice out of group:eng", capForm, 443, "carol")

	// A policy edit putting bob in grants through a stamp, sent as a patch.
	setCapPolicy(t, srv, `{
		"groups": {"group:eng": ["carol@", "bob@"]},
		"tagOwners": {"tag:web": ["ops@"], "tag:dev": ["ops@"], "tag:idle": ["ops@"]},
		"grants": [
			{"src": ["group:eng", "tag:dev"], "dst": ["tag:web"], "ip": ["tcp:443"]},
			{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:22"]}
		]
	}`)
	expect("bob into group:eng", capForm, 443, "bob", "carol")

	// A filter change alone.
	setCapPolicy(t, srv, `{
		"groups": {"group:eng": ["carol@", "bob@"]},
		"tagOwners": {"tag:web": ["ops@"], "tag:dev": ["ops@"], "tag:idle": ["ops@"]},
		"grants": [
			{"src": ["group:eng", "tag:dev"], "dst": ["tag:web"], "ip": ["tcp:8443"]},
			{"src": ["*"], "dst": ["tag:web"], "ip": ["tcp:22"]}
		]
	}`)
	expect("port moved", capForm, 8443, "bob", "carol")

	// A holder removed: its address no longer names a peer.
	carolNode, ok := st.GetNodeByID(findNodeID(t, srv, "carol-laptop"))
	require.True(t, ok)
	require.NoError(t, st.DeleteNode(carolNode))
	expect("carol removed", capForm, 8443, "bob")

	require.Equal(t, "equal", freshNetmapDifference(srv, webID, netmapOf(t)), "the backend holds what a fresh session is sent")
}
