package servertest_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/control/controlclient"
	"tailscale.com/ipn"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsnet"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/types/persist"
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

	requireHoldsFresh(t, srv, "stamped", web)

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

	requireHoldsFresh(t, srv, "dev retagged", web)

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

	requireHoldsFresh(t, srv, "alice renamed", web)

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

	requireHoldsFresh(t, srv, "announcing", web)

	nm = web.Netmap()
	require.True(t, admits(t, nm, aIP, 443))
	require.False(t, admits(t, nm, bIP, 443))

	announce()

	web.WaitForCondition(t, "capability form again", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return slices.Equal(capRuleSources(nm), []string{"cap:" + capEng, "cap:" + capDev})
	})

	requireHoldsFresh(t, srv, "capability form again", web)
}

func isCapSource(src string) bool { return strings.HasPrefix(src, "cap:") }

// TestCapabilitySourcesRefusedReport: the client widens its local nets from
// its own preferences whether or not the server keeps its report, so a
// report refused for its size that starts announcing a route, or running as
// an app connector, still sends the node addresses, over its live stream
// and after a restart. The rest of the report stays refused.
func TestCapabilitySourcesRefusedReport(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		widen func(*tailcfg.Hostinfo)
	}{
		{"announces a route", func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")} }},
		{"app connector", func(hi *tailcfg.Hostinfo) { hi.AppConnector.Set(true) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := servertest.NewServer(t, servertest.WithCapabilitySources())
			setCapPolicy(t, srv, capSourcesPolicy)

			ops := srv.CreateUser(t, "ops")
			alice := srv.CreateUser(t, "alice")

			web := servertest.NewClient(t, srv, "web", servertest.WithUser(ops), servertest.WithTags("tag:web"))
			aIP := ipv4Of(t, servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice)))
			id := findNodeID(t, srv, "web")

			web.WaitForCondition(t, "capability form", 10*time.Second, func(nm *netmap.NetworkMap) bool {
				return slices.Contains(capRuleSources(nm), "cap:"+capEng)
			})

			streams, _ := web.Stream()

			hi := &tailcfg.Hostinfo{
				BackendLogID: "servertest-web", Hostname: "web", GoVersion: "go1.27.3", IPNVersion: "1.94.1",
				OSVersion: strings.Repeat("v", types.MaxHostinfoSize),
			}
			tc.widen(hi)
			web.Direct().SetHostinfo(hi)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			require.ErrorContains(t, web.Direct().SendUpdate(ctx), "initial fetch failed 413")

			web.WaitForCondition(t, "address form after the refusal", 10*time.Second, func(nm *netmap.NetworkMap) bool {
				srcs := capRuleSources(nm)

				return slices.Contains(srcs, aIP.String()) && !slices.ContainsFunc(srcs, isCapSource)
			})

			now, _ := web.Stream()
			require.Equal(t, streams, now, "the refusal leaves the stream up")
			require.True(t, web.Polling())

			nv, ok := srv.State().GetNodeByID(id)
			require.True(t, ok)
			require.Empty(t, nv.Hostinfo().OSVersion(), "the rest of the report stays refused")

			srv.Restart(t)

			served, err := srv.State().Snapshot().FilterForNode(id)
			require.NoError(t, err)
			require.NotEmpty(t, served)

			for _, r := range served {
				require.False(t, slices.ContainsFunc(r.SrcIPs, isCapSource), "after a restart: %v", r.SrcIPs)
			}
		})
	}
}

// netmapObserver is a [controlclient.Observer] handing seen each network
// map the client receives.
type netmapObserver func(*netmap.NetworkMap)

func (seen netmapObserver) SetControlClientStatus(_ controlclient.Client, st controlclient.Status) {
	if st.NetMap != nil {
		seen(st.NetMap)
	}
}

// TestAutoClientRefusedReportKeepsStream runs tailscaled's own control
// client: a Hostinfo change goes out in a lite update of its own, which the
// client retries when it is refused while its stream stays up, so the
// address form reaches it over that stream.
func TestAutoClientRefusedReportKeepsStream(t *testing.T) {
	t.Parallel()

	srv := servertest.NewServer(t, servertest.WithCapabilitySources())
	setCapPolicy(t, srv, `{
		"groups": {"group:eng": ["alice@"]},
		"grants": [{"src": ["group:eng"], "dst": ["router@"], "ip": ["tcp:443"]}]
	}`)

	router := srv.CreateUser(t, "router")
	alice := srv.CreateUser(t, "alice")
	aIP := ipv4Of(t, servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice)))

	var held atomic.Pointer[netmap.NetworkMap]

	hi := &tailcfg.Hostinfo{BackendLogID: "servertest-auto-router", Hostname: "auto-router", GoVersion: "go1.27.3", IPNVersion: "1.94.1"}
	auto := servertest.NewAutoClient(t, srv, router, hi.Clone(), netmapObserver(held.Store))

	sources := func() []string {
		if nm := held.Load(); nm != nil {
			return capRuleSources(nm)
		}

		return nil
	}

	require.Eventually(t, func() bool { return slices.Contains(sources(), "cap:"+capEng) },
		10*time.Second, 10*time.Millisecond, "capability form")

	id := findNodeID(t, srv, "auto-router")
	before, ok := srv.State().GetNodeByID(id)
	require.True(t, ok)

	refused := hi.Clone()
	refused.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.9.0.0/24")}
	refused.OSVersion = strings.Repeat("v", types.MaxHostinfoSize)
	auto.SetHostinfo(refused)

	require.Eventually(t, func() bool {
		srcs := sources()

		return slices.Contains(srcs, aIP.String()) && !slices.ContainsFunc(srcs, isCapSource)
	}, 10*time.Second, 10*time.Millisecond, "address form over the stream")

	after, ok := srv.State().GetNodeByID(id)
	require.True(t, ok)
	require.Equal(t, before.SessionEpoch(), after.SessionEpoch(), "no new stream: a stream carrying the report is refused too")
	require.Empty(t, after.Hostinfo().OSVersion(), "the report was refused")
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
//
// Each delivery pins its test switch, as [TestFilterDeliveryThroughClient]
// does.
func TestCapabilitySourcesThroughLocalBackend(t *testing.T) {
	for _, chunks := range []bool{false, true} {
		t.Run(fmt.Sprintf("filter_chunks=%t", chunks), func(t *testing.T) {
			t.Setenv(state.TestFilterChunksEnv, strconv.FormatBool(chunks))
			testCapabilitySourcesThroughLocalBackend(t, chunks)
		})
	}
}

func testCapabilitySourcesThroughLocalBackend(t *testing.T, chunks bool) {
	t.Helper()

	opts := []servertest.ServerOption{servertest.WithCapabilitySources(), servertest.WithRealListener()}
	if chunks {
		opts = append(opts, servertest.WithFilterChunks())
	}

	srv := servertest.NewServer(t, opts...)
	st := srv.State()

	require.Equal(t, chunks, st.Snapshot().FilterChunks(), "test sanity: filter chunks as the subtest says")

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
	// on port, once form holds of the sources web holds, and for the
	// backend to hold what a fresh session is sent, its chunks answering
	// as the filter served as one list.
	expect := func(step string, form func([]string) bool, port uint16, admitted ...string) {
		t.Helper()

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			assert.True(ct, form(rulesOf(t)), "%s: filter form", step)

			nm := netmapOf(t)
			assert.Equal(ct, "equal", freshNetmapDifference(srv, webID, nm), "%s: the backend holds what a fresh session is sent", step)
			assert.Empty(ct, enforcesServed(t, srv, webID, nm), "%s: the chunks it holds answer as the filter served", step)

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

// enforcesServed reports how the filter a client assembled from the chunks
// it holds (nm's rules) answers otherwise than the filter the server
// serves node id as one list, through the client's own filter: every
// verdict from every address the netmap and the rules name, to every
// address the node holds or routes, on every port edge, by TCP, UDP and
// ICMP, and every app capability's values in order. "" when it does not.
func enforcesServed(t *testing.T, srv *servertest.TestServer, id types.NodeID, nm *netmap.NetworkMap) string {
	t.Helper()

	served, err := srv.State().Snapshot().FilterForNode(id)
	require.NoError(t, err)

	var b netipx.IPSetBuilder

	for _, p := range nm.SelfNode.Addresses().All() {
		b.AddPrefix(p)
	}

	for _, p := range nm.SelfNode.Hostinfo().RoutableIPs().All() {
		b.AddPrefix(p)
	}

	local, err := b.IPSet()
	require.NoError(t, err)

	build := func(rules []tailcfg.FilterRule) *filter.Filter {
		ms, err := filter.MatchesFromFilterRules(rules)
		require.NoError(t, err)

		return filter.New(ms, servertest.CapLookup(nm), local, nil, nil, logger.Discard)
	}

	assembled := nm.PacketFilterRules.AsSlice()
	one, got := build(served), build(assembled)

	srcs := []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")}
	dsts := []netip.Addr{}
	ports := []uint16{0, 1, 22, 53, 80, 443, 8080, 65535}

	for _, n := range append([]tailcfg.NodeView{nm.SelfNode}, nm.Peers...) {
		for _, p := range n.Addresses().All() {
			srcs = append(srcs, p.Addr())
		}
	}

	for _, p := range nm.SelfNode.Addresses().All() {
		dsts = append(dsts, p.Addr())
	}

	for _, r := range slices.Concat(served, assembled) {
		for _, d := range r.DstPorts {
			ports = append(ports, d.Ports.First, d.Ports.Last, d.Ports.First-1, d.Ports.Last+1)

			p, err := netip.ParsePrefix(d.IP)
			if err != nil {
				a, aerr := netip.ParseAddr(d.IP)
				if aerr != nil {
					continue
				}

				p = netip.PrefixFrom(a, a.BitLen())
			}

			dsts = append(dsts, p.Addr())
		}
	}

	slices.SortFunc(srcs, netip.Addr.Compare)
	slices.SortFunc(dsts, netip.Addr.Compare)
	slices.Sort(ports)

	for _, src := range slices.Compact(srcs) {
		for _, dst := range slices.Compact(dsts) {
			if src.Is4() != dst.Is4() {
				continue
			}

			if a, b := one.CapsWithValues(src, dst), got.CapsWithValues(src, dst); !reflect.DeepEqual(a, b) {
				return fmt.Sprintf("caps %s -> %s: one list %v, chunks %v", src, dst, a, b)
			}

			icmp := ipproto.ICMPv4
			if src.Is6() {
				icmp = ipproto.ICMPv6
			}

			for _, proto := range []ipproto.Proto{ipproto.TCP, ipproto.UDP, icmp} {
				for _, port := range slices.Compact(ports) {
					if a, b := one.Check(src, dst, port, proto), got.Check(src, dst, port, proto); a != b {
						return fmt.Sprintf("%s %s -> %s:%d: one list %v, chunks %v", proto, src, dst, port, a, b)
					}
				}
			}
		}
	}

	return ""
}

// requireHoldsFresh waits for the filter c assembled to be what a fresh
// session of its node is sent, and holds it to the filter served as one
// list through c's own filter.
func requireHoldsFresh(t *testing.T, srv *servertest.TestServer, step string, c *servertest.TestClient) {
	t.Helper()

	id := findNodeID(t, srv, c.Name)

	require.Eventuallyf(t, func() bool {
		return freshNetmapDifference(srv, id, c.Netmap()) == "equal"
	}, 10*time.Second, 20*time.Millisecond, "%s: %s holds what a fresh session is sent: %s", step, c.Name, freshNetmapDifference(srv, id, c.Netmap()))

	require.Emptyf(t, enforcesServed(t, srv, id, c.Netmap()), "%s: %s", step, c.Name)
}

// TestCanaryClientChunkMerge pins how the control client merges packet
// filter chunks, as one response's map session applies them: the singular
// PacketFilter sets "base", "*": null clears everything before the rest
// applies, a null chunk is deleted, and the chunks are concatenated in key
// order. policyv2.FilterChunks models it for every check of what a client
// assembles; across responses, the sessions of
// TestFilterDeliveryThroughClient pin it.
func TestCanaryClientChunkMerge(t *testing.T) {
	t.Parallel()

	rule := func(port uint16) tailcfg.FilterRule {
		return tailcfg.FilterRule{
			SrcIPs:   []string{"100.64.0.2"},
			DstPorts: []tailcfg.NetPortRange{{IP: "100.64.0.1", Ports: tailcfg.PortRange{First: port, Last: port}}},
		}
	}
	a, b, c := rule(1), rule(2), rule(3)
	pr := (&persist.Persist{PrivateNodeKey: key.NewNode()}).View()

	for _, tt := range []struct {
		name     string
		singular []tailcfg.FilterRule
		chunks   map[string][]tailcfg.FilterRule
		want     []tailcfg.FilterRule
	}{
		{name: "singular is base", singular: []tailcfg.FilterRule{a}, want: []tailcfg.FilterRule{a}},
		{name: "singular then chunks, in key order", singular: []tailcfg.FilterRule{b}, chunks: map[string][]tailcfg.FilterRule{"a": {a}, "c": {c}}, want: []tailcfg.FilterRule{a, b, c}},
		{name: "clear drops the singular", singular: []tailcfg.FilterRule{a}, chunks: map[string][]tailcfg.FilterRule{"*": nil, "x": {b}}, want: []tailcfg.FilterRule{b}},
		{name: "null deletes", singular: []tailcfg.FilterRule{a}, chunks: map[string][]tailcfg.FilterRule{"base": nil, "x": {b}}, want: []tailcfg.FilterRule{b}},
		{name: "key order, not map order", chunks: map[string][]tailcfg.FilterRule{"r/b": {b}, "c/a": {a, c}, "r/a": {c}}, want: []tailcfg.FilterRule{a, c, c, b}},
		{name: "clear alone empties", chunks: map[string][]tailcfg.FilterRule{"*": nil}, want: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sent := &tailcfg.MapResponse{
				Node:          &tailcfg.Node{ID: 1, Name: "n.example.", Key: key.NewNode().Public(), Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")}},
				PacketFilter:  tt.singular,
				PacketFilters: tt.chunks,
			}

			// Through the bytes, as the client reads them: the encoder the
			// server writes with, the decoder the client reads with, a
			// null chunk decoded as nil.
			wire, err := mapper.Marshal(sent)
			require.NoError(t, err)

			resp := &tailcfg.MapResponse{}
			require.NoError(t, json.Unmarshal(wire, resp))

			for name, rules := range tt.chunks {
				if rules == nil {
					require.Contains(t, string(wire), `"`+name+`":null`)
					require.Contains(t, resp.PacketFilters, name)
					require.Nil(t, resp.PacketFilters[name])
				}
			}

			nm, err := controlclient.NetmapFromMapResponseForDebug(t.Context(), pr, resp)
			require.NoError(t, err)

			got := nm.PacketFilterRules.AsSlice()
			require.Equal(t, tt.want, got, "the client")
			require.Equal(t, got, policyv2.FilterChunks{}.ApplyResponse(resp).Rules(), "the model of it")
		})
	}
}

// TestFilterDeliveryThroughClient is check C for filter delivery, in each
// combination of policy.capability_sources and policy.filter_chunks: real
// control clients, one taking filter updates in place as tailscaled does,
// through policy edits that remove, edit and reorder rules, a receiver
// flipping to addresses and back, a member leaving an address-form rule,
// and reconnects. After each, every client holds what a fresh session of
// its node is sent, and the filter it assembled from what it holds answers
// as the filter served as one list.
//
// Each combination pins both test switches too, so a subtest that says an
// option is off runs with it off whatever the suite's switches say; so the
// subtests run one at a time.
func TestFilterDeliveryThroughClient(t *testing.T) {
	for _, capSources := range []bool{false, true} {
		for _, chunks := range []bool{false, true} {
			t.Run(fmt.Sprintf("capability_sources=%t/filter_chunks=%t", capSources, chunks), func(t *testing.T) {
				t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))
				t.Setenv(state.TestFilterChunksEnv, strconv.FormatBool(chunks))
				testFilterDeliveryThroughClient(t, capSources, chunks)
			})
		}
	}
}

func testFilterDeliveryThroughClient(t *testing.T, capSources, chunks bool) {
	t.Helper()

	doc := `{"groups":{"group:eng":["alice@"],"group:ops":["bob@"]},
		"tagOwners":{"tag:web":["ops@"],"tag:idle":["ops@"]},
		"grants":[
			{"src":["group:eng"],"dst":["tag:web"],"ip":["tcp:443","udp:53"]},
			{"src":["group:ops"],"dst":["tag:web"],"ip":["tcp:22"]},
			{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["tcp:8080"]},
			{"src":["group:eng"],"dst":["tag:web"],"app":{"example.com/cap/x":[{"v":1},{"v":"second"}]}},
			{"src":["autogroup:member"],"dst":["tag:web"],"app":{"example.com/cap/x":[{"v":"m"}]}},
			{"src":["alice@"],"dst":["tag:web"],"app":{"example.com/cap/x":[{"v":"a"}]}},
			{"src":["group:ops"],"dst":["tag:web"],"app":{"example.com/cap/y":[{"v":2}]}}
		]}`

	var opts []servertest.ServerOption
	if capSources {
		opts = append(opts, servertest.WithCapabilitySources())
	}

	if chunks {
		opts = append(opts, servertest.WithFilterChunks())
	}

	srv := servertest.NewServer(t, opts...)
	setCapPolicy(t, srv, doc)

	require.Equal(t, capSources, srv.State().Snapshot().CapabilitySources(), "test sanity: capability sources as the subtest says")
	require.Equal(t, chunks, srv.State().Snapshot().FilterChunks(), "test sanity: filter chunks as the subtest says")

	ops := srv.CreateUser(t, "ops")
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")

	web := servertest.NewClient(t, srv, "web", servertest.WithUser(ops), servertest.WithTags("tag:web"))
	delta := servertest.NewClient(t, srv, "web-delta", servertest.WithUser(ops), servertest.WithTags("tag:web"), servertest.WithDeltaUpdates())
	a := servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice))
	a2 := servertest.NewClient(t, srv, "alice-phone", servertest.WithUser(alice))
	b := servertest.NewClient(t, srv, "bob-laptop", servertest.WithUser(bob))
	clients := []*servertest.TestClient{web, delta, a, a2, b}

	holdFresh := func(step string) {
		t.Helper()

		for _, c := range clients {
			requireHoldsFresh(t, srv, step, c)
		}
	}

	holdFresh("start")

	edit := func(step, old, next string) {
		t.Helper()
		require.Contains(t, doc, old)
		doc = strings.Replace(doc, old, next, 1)
		setCapPolicy(t, srv, doc)
		holdFresh(step)
	}

	edit("rule removed", `{"src":["group:ops"],"dst":["tag:web"],"ip":["tcp:22"]},`+"\n\t\t\t", "")
	edit("port edited", `"tcp:443"`, `"tcp:8443"`)
	edit("protocol edited", `"udp:53"`, `"tcp:53"`)
	edit("capability value edited", `{"v":1}`, `{"v":3}`)
	edit("a capability's second value edited", `{"v":"second"}`, `{"v":"2nd"}`)
	// alice's applications on web read example.com/cap/x's values in
	// policy order, which reordering the grants changes.
	edit("app rules reordered",
		`{"src":["group:eng"],"dst":["tag:web"],"app":{"example.com/cap/x":[{"v":3},{"v":"2nd"}]}},
			{"src":["autogroup:member"],"dst":["tag:web"],"app":{"example.com/cap/x":[{"v":"m"}]}},`,
		`{"src":["autogroup:member"],"dst":["tag:web"],"app":{"example.com/cap/x":[{"v":"m"}]}},
			{"src":["group:eng"],"dst":["tag:web"],"app":{"example.com/cap/x":[{"v":3},{"v":"2nd"}]}},`)
	edit("rules reordered",
		`{"src":["group:eng"],"dst":["tag:web"],"ip":["tcp:8443","tcp:53"]},
			{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["tcp:8080"]},`,
		`{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["tcp:8080"]},
			{"src":["group:eng"],"dst":["tag:web"],"ip":["tcp:8443","tcp:53"]},`)

	// web announces a route: everything it is sent goes as addresses, and
	// a member leaving group:eng moves only the rules that name it.
	announce := func(routes ...netip.Prefix) {
		t.Helper()

		web.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-web", Hostname: "web", RoutableIPs: routes, GoVersion: "go1.27.3", IPNVersion: "1.94.1",
		})

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		require.NoError(t, web.Direct().SendUpdate(ctx))
	}

	aIP := ipv4Of(t, a2)

	announce(netip.MustParsePrefix("10.9.0.0/24"))
	web.WaitForCondition(t, "address form while announcing", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return slices.Contains(capRuleSources(nm), aIP.String())
	})
	holdFresh("form flipped to addresses")

	_, err := srv.State().SetNodeTags(findNodeID(t, srv, "alice-phone"), []string{"tag:idle"})
	require.NoError(t, err)
	web.WaitForCondition(t, "alice-phone left group:eng", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return !slices.Contains(capRuleSources(nm), aIP.String())
	})
	holdFresh("member of an address-form rule left")

	announce()
	web.WaitForCondition(t, "the source form again", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return capSources == slices.ContainsFunc(capRuleSources(nm), func(s string) bool { return strings.HasPrefix(s, "cap:") })
	})
	holdFresh("form flipped back")

	// A reconnect: the Go client starts its new map session holding no
	// chunk, and the server's first response clears whatever it held.
	for _, c := range []*servertest.TestClient{web, delta} {
		c.Reconnect(t)
	}

	holdFresh("reconnected")

	edit("edit after the reconnect", `"tcp:8080"`, `"tcp:8081"`)
}
