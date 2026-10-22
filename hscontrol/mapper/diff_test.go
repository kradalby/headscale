package mapper

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func testPeer(id tailcfg.NodeID) *tailcfg.Node {
	return &tailcfg.Node{
		ID:        id,
		Key:       key.NewNode().Public(),
		HomeDERP:  1,
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")},
		Online:    new(true),
		Addresses: []netip.Prefix{netip.MustParsePrefix("100.64.0.1/32")},
	}
}

func cloneNode(n *tailcfg.Node) *tailcfg.Node { return n.Clone() }

func testNetMap(peers ...*tailcfg.Node) *netMap {
	return &netMap{
		self:     testPeer(1),
		peers:    peerMapOf(peers...),
		profiles: map[tailcfg.UserID]tailcfg.UserProfile{1: {ID: 1, LoginName: "a"}},
		filter:   []tailcfg.FilterRule{{SrcIPs: []string{"*"}}},
		ssh:      &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}},
	}
}

func peerMapOf(peers ...*tailcfg.Node) *peerMap {
	e := newPeerMap().Edit()
	for _, p := range peers {
		e.Set(p.ID, p)
	}

	return e.Done()
}

// withPeers returns a copy of nm with its peers replaced.
func withPeers(nm *netMap, peers ...*tailcfg.Node) *netMap {
	c := *nm
	c.peers = peerMapOf(peers...)

	return &c
}

func TestDiffUnchangedSendsNothing(t *testing.T) {
	p := testPeer(2)
	sent := testNetMap(p)
	// A fresh render of the same data holds new pointers.
	next := withPeers(sent, cloneNode(p))
	next.ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}

	if got := diff(sent, next); got != nil {
		t.Fatalf("diff of equal maps = %+v, want nil", got)
	}
}

func TestDiffEndpointChangeIsPatch(t *testing.T) {
	p := testPeer(2)
	moved := cloneNode(p)
	moved.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}

	sent := testNetMap(p)

	got := diff(sent, withPeers(sent, moved))
	if len(got) != 1 {
		t.Fatalf("got %d responses, want 1", len(got))
	}

	r := got[0]
	if len(r.PeersChangedPatch) != 1 || len(r.PeersChanged) != 0 || r.Peers != nil {
		t.Fatalf("want one patch only, got %+v", r)
	}

	if r.Node != nil || r.SSHPolicy != nil || r.DNSConfig != nil || r.PacketFilters != nil {
		t.Fatalf("patch-only change carried non-patch fields: %+v", r)
	}
}

func TestDiffOnlineTransitions(t *testing.T) {
	online := testPeer(2)

	offline := cloneNode(online)
	offline.Online = new(false)
	seen := time.Unix(1700000000, 0)
	offline.LastSeen = &seen

	sent := testNetMap(online)

	got := diff(sent, withPeers(sent, offline))
	if len(got) != 1 || len(got[0].PeersChangedPatch) != 1 {
		t.Fatalf("offline: want one patch, got %+v", got)
	}

	if pc := got[0].PeersChangedPatch[0]; pc.Online == nil || *pc.Online || pc.LastSeen == nil {
		t.Fatalf("offline patch = %+v, want Online=false with LastSeen", pc)
	}

	// Coming back online drops LastSeen, which a patch cannot clear; the
	// Online patch is still sent rather than a full peer.
	got = diff(withPeers(sent, offline), withPeers(sent, cloneNode(online)))
	if len(got) != 1 || len(got[0].PeersChangedPatch) != 1 || len(got[0].PeersChanged) != 0 {
		t.Fatalf("online: want one patch, got %+v", got)
	}

	if pc := got[0].PeersChangedPatch[0]; pc.Online == nil || !*pc.Online {
		t.Fatalf("online patch = %+v, want Online=true", pc)
	}
}

func TestDiffUnpatchableFieldSendsWholePeer(t *testing.T) {
	p := testPeer(2)
	expired := cloneNode(p)
	expired.Expired = true

	sent := testNetMap(p)

	got := diff(sent, withPeers(sent, expired))
	if len(got) != 1 || len(got[0].PeersChanged) != 1 || len(got[0].PeersChangedPatch) != 0 {
		t.Fatalf("want one whole peer, got %+v", got)
	}
}

func TestDiffDERPClearSendsPeerList(t *testing.T) {
	p, q := testPeer(2), testPeer(3)
	cleared := cloneNode(p)
	cleared.HomeDERP = 0

	sent := testNetMap(p, q)

	got := diff(sent, withPeers(sent, cleared, q))
	if len(got) != 1 || len(got[0].Peers) != 2 {
		t.Fatalf("want the whole peer list, got %+v", got)
	}

	if len(got[0].PeersChanged)+len(got[0].PeersChangedPatch) != 0 {
		t.Fatalf("peer list combined with deltas: %+v", got[0])
	}
}

func TestDiffRemovalLeadsOnItsOwn(t *testing.T) {
	p, q := testPeer(2), testPeer(3)

	sent := testNetMap(p, q)

	got := diff(sent, withPeers(sent, q))
	if len(got) != 1 || len(got[0].PeersRemoved) != 1 || got[0].PeersRemoved[0] != 2 {
		t.Fatalf("removal only: got %+v", got)
	}

	next := withPeers(sent, q)
	next.ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{Principals: []*tailcfg.SSHPrincipal{{Any: true}}}}}

	got = diff(sent, next)
	if len(got) != 2 {
		t.Fatalf("want removal then update, got %d responses", len(got))
	}

	if len(got[0].PeersRemoved) != 1 || got[0].SSHPolicy != nil {
		t.Fatalf("first response = %+v, want only the removal", got[0])
	}

	if got[1].SSHPolicy == nil || len(got[1].PeersRemoved) != 0 {
		t.Fatalf("second response = %+v, want the SSH policy only", got[1])
	}
}

func TestDiffSendsOnlyChangedSections(t *testing.T) {
	sent := testNetMap(testPeer(2))

	self := cloneNode(sent.self)
	self.Name = "renamed."
	next := *sent
	next.self = self
	next.filter = []tailcfg.FilterRule{{SrcIPs: []string{"100.64.0.2/32"}}}

	got := diff(sent, &next)
	if len(got) != 1 {
		t.Fatalf("got %d responses, want 1", len(got))
	}

	r := got[0]
	if r.Node == nil || r.PacketFilters == nil {
		t.Fatalf("missing changed sections: %+v", r)
	}

	if r.SSHPolicy != nil || r.DNSConfig != nil || r.DERPMap != nil || len(r.UserProfiles) != 0 {
		t.Fatalf("unchanged sections resent: %+v", r)
	}
}

func TestDiffNewPeerCarriesItsProfile(t *testing.T) {
	sent := testNetMap()
	p := testPeer(2)
	p.User = 2
	next := withPeers(sent, p)
	next.profiles = map[tailcfg.UserID]tailcfg.UserProfile{
		1: sent.profiles[1],
		2: {ID: 2, LoginName: "b"},
	}

	got := diff(sent, next)
	if len(got) != 1 || len(got[0].PeersChanged) != 1 {
		t.Fatalf("want the new peer, got %+v", got)
	}

	if len(got[0].UserProfiles) != 1 || got[0].UserProfiles[0].ID != 2 {
		t.Fatalf("profiles = %+v, want only the new user's", got[0].UserProfiles)
	}
}

// patchableFields are the [tailcfg.Node] fields [peerPatch] carries in a
// [tailcfg.PeerChange]; every other field must be compared by
// [peerRestEqual].
var patchableFields = map[string]bool{
	"HomeDERP": true, "Endpoints": true, "Key": true, "DiscoKey": true, "KeyExpiry": true,
	"Online": true, "LastSeen": true, "KeySignature": true, "Cap": true, "CapMap": true,
}

// TestPeerRestEqualCoversEveryField changes each non-patchable field of a
// peer in turn and requires peerRestEqual to see it, so a field added to
// tailcfg.Node fails here instead of being silently patched away.
func TestPeerRestEqualCoversEveryField(t *testing.T) {
	base := testPeer(2)

	typ := reflect.TypeFor[tailcfg.Node]()
	for i := range typ.NumField() {
		f := typ.Field(i)
		// Unexported fields never reach the wire.
		if patchableFields[f.Name] || !f.IsExported() {
			continue
		}

		t.Run(f.Name, func(t *testing.T) {
			changed := base.Clone()
			v := reflect.ValueOf(changed).Elem().Field(i)

			if !setDifferent(v) {
				t.Fatalf("no way to change field %s of kind %s; teach setDifferent and peerRestEqual about it", f.Name, v.Kind())
			}

			if peerRestEqual(base, changed) {
				t.Fatalf("peerRestEqual misses a change to %s", f.Name)
			}
		})
	}
}

// setDifferent sets v to a value different from the testPeer default.
func setDifferent(v reflect.Value) bool {
	switch v.Type() {
	case reflect.TypeFor[time.Time]():
		v.Set(reflect.ValueOf(time.Unix(1, 0)))

		return true
	case reflect.TypeFor[tailcfg.HostinfoView]():
		v.Set(reflect.ValueOf((&tailcfg.Hostinfo{Hostname: "changed"}).View()))

		return true
	case reflect.TypeFor[key.MachinePublic]():
		v.Set(reflect.ValueOf(key.NewMachine().Public()))

		return true
	}

	switch v.Kind() { //nolint:exhaustive // other kinds fail the test below
	case reflect.String:
		v.SetString(v.String() + "x")
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
	case reflect.Slice:
		v.Set(reflect.Append(v, reflect.New(v.Type().Elem()).Elem()))
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
	case reflect.Array:
		// Keys are fixed-size arrays; flip a byte.
		b := v.Index(v.Len() - 1)
		b.SetUint(b.Uint() + 1)
	default:
		return false
	}

	return true
}

// TestWithRoutesMatchesTailNode checks that a shared render plus one
// viewer's routes is exactly what rendering the peer with those routes
// gives.
func TestWithRoutesMatchesTailNode(t *testing.T) {
	uid := uint(1)
	v4 := netip.MustParseAddr("100.64.0.9")
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::9")
	routes := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	}

	peer := (&types.Node{
		ID:         9,
		GivenName:  "peer",
		Hostname:   "peer",
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		IPv4:       &v4,
		IPv6:       &v6,
		UserID:     &uid,
		User:       &types.User{Name: "u"},
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "peer"},
	}).View()

	cfg := &types.Config{BaseDomain: "example.com"}

	want, err := peer.TailNode(capVer, func(types.NodeID) []netip.Prefix { return routes }, cfg, nil)
	if err != nil {
		t.Fatal(err)
	}

	base, err := (&peerRenders{}).render(cfg, capVer, 1, peer, nil)
	if err != nil {
		t.Fatal(err)
	}

	got := withRoutes(base, routes)

	// render sets the peer-view CapMap and strips NetInfo; align those.
	want.CapMap = got.CapMap
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("shared render differs:\nwant %+v\ngot  %+v", want, got)
	}

	if len(base.PrimaryRoutes) != 0 || len(base.AllowedIPs) != 2 {
		t.Fatalf("withRoutes modified the shared base: %+v", base)
	}
}

// TestSameProfileCoversEveryField fails when tailcfg.UserProfile gains a
// field sameProfile does not compare.
func TestSameProfileCoversEveryField(t *testing.T) {
	typ := reflect.TypeFor[tailcfg.UserProfile]()
	require.Equal(t, 5, typ.NumField(), "compare the new UserProfile field in sameProfile")

	base := tailcfg.UserProfile{ID: 1, LoginName: "a", DisplayName: "A", ProfilePicURL: "p", Groups: []string{"g"}}
	require.True(t, sameProfile(base, base))

	for i := range typ.NumField() {
		changed := base
		v := reflect.ValueOf(&changed).Elem().Field(i)

		switch v.Kind() { //nolint:exhaustive // other kinds fail the test
		case reflect.String:
			v.SetString("other")
		case reflect.Int64:
			v.SetInt(2)
		case reflect.Slice:
			v.Set(reflect.ValueOf([]string{"h"}))
		default:
			t.Fatalf("field %s: unhandled kind %s", typ.Field(i).Name, v.Kind())
		}

		require.False(t, sameProfile(base, changed), "field %s", typ.Field(i).Name)
	}
}
