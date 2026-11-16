package mapper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/mem"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/types/opt"
	"tailscale.com/util/zstdframe"
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

// TestBuildMapRequestChangeResponse ports the state's nine response-classifier
// rows to the actual wire diff. Unlike the old event payload, a graph diff does
// not repeat unchanged keys/endpoints. Clearing DERP needs a full peer list.
func TestBuildMapRequestChangeResponse(t *testing.T) {
	capturedKeys, capturedEndpoints := saasDiscoRotation(t)
	require.True(t, capturedKeys, "SaaS repeats the node key alongside the rotated disco key")
	require.True(t, capturedEndpoints, "SaaS repeats unchanged endpoints; the graph diff below omits them")

	before := testPeer(7)
	before.DiscoKey = key.NewDisco().Public()
	before.Hostinfo = (&tailcfg.Hostinfo{Hostname: "peer", OS: "linux"}).View()
	disco := key.NewDisco().Public()

	endpoints := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.9:41641")}
	for _, tt := range []struct {
		name  string
		edit  func(*tailcfg.Node)
		kind  string
		patch *tailcfg.PeerChange
	}{
		{name: "nothing peer visible", edit: func(*tailcfg.Node) {}, kind: "none"},
		{name: "peer visible hostinfo", edit: func(n *tailcfg.Node) {
			n.Hostinfo = (&tailcfg.Hostinfo{Hostname: "peer", OS: "linux", Services: []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 4242}}}).View()
		}, kind: "peer"},
		{name: "derp clear to zero", edit: func(n *tailcfg.Node) { n.HomeDERP = 0 }, kind: "list"},
		{name: "disco key and derp clear to zero", edit: func(n *tailcfg.Node) { n.DiscoKey, n.HomeDERP = disco, 0 }, kind: "list"},
		{name: "disco key only", edit: func(n *tailcfg.Node) { n.DiscoKey = disco }, kind: "patch", patch: &tailcfg.PeerChange{NodeID: 7, DiscoKey: &disco}},
		{name: "disco key and derp move", edit: func(n *tailcfg.Node) { n.DiscoKey, n.HomeDERP = disco, 2 }, kind: "patch", patch: &tailcfg.PeerChange{NodeID: 7, DiscoKey: &disco, DERPRegion: 2}},
		{name: "useful endpoint only", edit: func(n *tailcfg.Node) { n.Endpoints = endpoints }, kind: "patch", patch: &tailcfg.PeerChange{NodeID: 7, Endpoints: endpoints}},
		{name: "derp move only", edit: func(n *tailcfg.Node) { n.HomeDERP = 2 }, kind: "patch", patch: &tailcfg.PeerChange{NodeID: 7, DERPRegion: 2}},
		{name: "endpoint and derp move", edit: func(n *tailcfg.Node) { n.Endpoints, n.HomeDERP = endpoints, 2 }, kind: "patch", patch: &tailcfg.PeerChange{NodeID: 7, Endpoints: endpoints, DERPRegion: 2}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			after := before.Clone()
			tt.edit(after)

			sent := testNetMap(before)

			got := diff(sent, withPeers(sent, after), nil)
			if tt.kind == "none" {
				require.Empty(t, got)
				return
			}

			want := &tailcfg.MapResponse{ControlTime: new(time.Time)}

			switch tt.kind {
			case "peer":
				want.PeersChanged = []*tailcfg.Node{after}
			case "list":
				want.Peers = []*tailcfg.Node{after}
			case "patch":
				want.PeersChangedPatch = []*tailcfg.PeerChange{tt.patch}
			}

			require.Equal(t, []*tailcfg.MapResponse{want}, got, "all response and patch fields must match")
		})
	}
}

// TestReauthChange retains the four reauthentication response classes without
// reconstructing a change.Change. A policy edit and keys share one exact diff.
func TestReauthChange(t *testing.T) {
	before := testPeer(7)
	before.DiscoKey = key.NewDisco().Public()
	after := before.Clone()
	after.Key, after.DiscoKey = key.NewNode().Public(), key.NewDisco().Public()
	patch := &tailcfg.PeerChange{NodeID: after.ID, Key: &after.Key, DiscoKey: &after.DiscoKey}

	for _, tt := range []struct {
		name string
	}{
		{name: "keys"},
		{name: "unchanged"},
		{name: "new node"},
		{name: "policy and keys"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			sent := testNetMap(before)
			next := withPeers(sent, after)
			want := &tailcfg.MapResponse{ControlTime: new(time.Time)}

			switch tt.name {
			case "keys":
				want.PeersChangedPatch = []*tailcfg.PeerChange{patch}
			case "unchanged":
				next = withPeers(sent, before.Clone())
			case "new node":
				sent = withPeers(sent)
				want.PeersChanged = []*tailcfg.Node{after}
			case "policy and keys":
				sent.ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{Action: &tailcfg.SSHAction{Accept: true}}}}
				next.filter = []tailcfg.FilterRule{}
				next.ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{}}
				want.PeersChangedPatch = []*tailcfg.PeerChange{patch}
				want.PacketFilters = map[string][]tailcfg.FilterRule{"base": {}}
				want.SSHPolicy = next.ssh
			}

			got := diff(sent, next, nil)
			if tt.name == "unchanged" {
				require.Empty(t, got)
				return
			}

			require.Equal(t, []*tailcfg.MapResponse{want}, got)
		})
	}
}

// TestReloginChanged keeps all six original state classifier rows, checking the
// peer's exact diff and the subject's complete self update through real streams.
func TestReloginChanged(t *testing.T) {
	for _, tt := range []struct {
		name      string
		rotate    bool
		past      bool
		osVersion bool
		service   bool
		renew     bool
		wholePeer bool
	}{
		{name: "keys", rotate: true},
		{name: "hostinfo peers do not read", rotate: true, osVersion: true},
		{name: "un-expired", rotate: true, past: true, wholePeer: true},
		{name: "hostinfo peers read", rotate: true, service: true, wholePeer: true},
		{name: "same keys"},
		{name: "same keys, new expiry", renew: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg, s, ids := streamTestState(t, "")
			before := mustNode(t, s, ids[0]).AsStruct()
			now := time.Now().UTC()
			future := now.Add(time.Hour)

			before.Expiry = new(future)
			if tt.past {
				before.Expiry = new(now.Add(-time.Minute))
			}

			before.Hostinfo = &tailcfg.Hostinfo{Hostname: "node", OS: "linux"}
			s.PutNodeInStoreForTest(*before)

			hub := NewHub()
			t.Cleanup(hub.Close)
			viewer := NewStream(cfg, hub, ids[2], capVer)
			self := NewStream(cfg, hub, ids[0], capVer)
			_, err := viewer.Initial(s.Snapshot())
			require.NoError(t, err)
			_, err = self.Initial(s.Snapshot())
			require.NoError(t, err)

			after := before.Clone()
			if tt.rotate {
				after.NodeKey, after.DiscoKey = key.NewNode().Public(), key.NewDisco().Public()
			}

			if tt.osVersion {
				after.Hostinfo.OSVersion = "6.1"
			}

			if tt.service {
				after.Hostinfo.Services = []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 4242}}
			}

			if tt.past {
				after.Expiry = new(future)
			}

			if tt.renew {
				after.Expiry = new(future.Add(time.Hour))
			}

			s.PutNodeInStoreForTest(*after)
			snap := s.Snapshot()
			got, err := viewer.Update(snap)
			require.NoError(t, err)
			own, err := self.Update(snap)
			require.NoError(t, err)

			if tt.name == "same keys" {
				require.Empty(t, got)
				require.Empty(t, own)

				return
			}

			want := &tailcfg.MapResponse{ControlTime: new(snap.Time())}

			if tt.wholePeer {
				freshHub := NewHub()
				defer freshHub.Close()

				fresh, err := NewStream(cfg, freshHub, ids[2], capVer).Initial(snap)
				require.NoError(t, err)

				for _, peer := range fresh[0].Peers {
					if peer.ID == ids[0].NodeID() {
						want.PeersChanged = []*tailcfg.Node{peer}
						assert.Equal(t, after.NodeKey, peer.Key)
						assert.Equal(t, after.DiscoKey, peer.DiscoKey)
						assert.Equal(t, *after.Expiry, peer.KeyExpiry)
						assert.False(t, peer.Expired)
						assert.Equal(t, after.Hostinfo.Services, peer.Hostinfo.Services().AsSlice())
					}
				}

				require.Len(t, want.PeersChanged, 1)
			} else {
				patch := &tailcfg.PeerChange{NodeID: ids[0].NodeID()}
				if tt.rotate {
					patch.Key, patch.DiscoKey = &after.NodeKey, &after.DiscoKey
				}

				if tt.renew {
					patch.KeyExpiry = after.Expiry
				}

				want.PeersChangedPatch = []*tailcfg.PeerChange{patch}
			}

			require.Equal(t, []*tailcfg.MapResponse{want}, got)

			freshHub := NewHub()
			defer freshHub.Close()

			fresh, err := NewStream(cfg, freshHub, ids[0], capVer).Initial(snap)
			require.NoError(t, err)
			require.Equal(t, []*tailcfg.MapResponse{{Node: fresh[0].Node, ControlTime: new(snap.Time())}}, own)
			assert.Equal(t, after.NodeKey, own[0].Node.Key)
			assert.Equal(t, after.DiscoKey, own[0].Node.DiscoKey)
			assert.Equal(t, *after.Expiry, own[0].Node.KeyExpiry)
		})
	}
}

func testNetMap(peers ...*tailcfg.Node) *netMap {
	return &netMap{
		self:     testPeer(1),
		peers:    peerMapOf(peers...),
		profiles: profileMapOf(tailcfg.UserProfile{ID: 1, LoginName: "a"}),
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

func profileMapOf(profiles ...tailcfg.UserProfile) *profileMap {
	e := newProfileMap().Edit()
	for _, p := range profiles {
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

	if got := diff(sent, next, nil); got != nil {
		t.Fatalf("diff of equal maps = %+v, want nil", got)
	}
}

func TestDiffEndpointChangeIsPatch(t *testing.T) {
	p := testPeer(2)
	moved := cloneNode(p)
	moved.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("198.51.100.7:41641")}

	sent := testNetMap(p)

	got := diff(sent, withPeers(sent, moved), nil)
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

	got := diff(sent, withPeers(sent, offline), nil)
	if len(got) != 1 || len(got[0].PeersChangedPatch) != 1 {
		t.Fatalf("offline: want one patch, got %+v", got)
	}

	if pc := got[0].PeersChangedPatch[0]; pc.Online == nil || *pc.Online || pc.LastSeen == nil {
		t.Fatalf("offline patch = %+v, want Online=false with LastSeen", pc)
	}

	// Coming back online drops LastSeen, which a patch cannot clear; the
	// Online patch is still sent rather than a full peer.
	got = diff(withPeers(sent, offline), withPeers(sent, cloneNode(online)), nil)
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

	got := diff(sent, withPeers(sent, expired), nil)
	if len(got) != 1 || len(got[0].PeersChanged) != 1 || len(got[0].PeersChangedPatch) != 0 {
		t.Fatalf("want one whole peer, got %+v", got)
	}
}

func TestDiffDERPClearSendsPeerList(t *testing.T) {
	p, q := testPeer(2), testPeer(3)
	cleared := cloneNode(p)
	cleared.HomeDERP = 0

	sent := testNetMap(p, q)

	got := diff(sent, withPeers(sent, cleared, q), nil)
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

	got := diff(sent, withPeers(sent, q), nil)
	if len(got) != 1 || len(got[0].PeersRemoved) != 1 || got[0].PeersRemoved[0] != 2 {
		t.Fatalf("removal only: got %+v", got)
	}

	next := withPeers(sent, q)
	next.ssh = &tailcfg.SSHPolicy{Rules: []*tailcfg.SSHRule{{Principals: []*tailcfg.SSHPrincipal{{Any: true}}}}}

	got = diff(sent, next, nil)
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

	got := diff(sent, &next, nil)
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
	own, _ := sent.profiles.Get(1)
	next.profiles = profileMapOf(own, tailcfg.UserProfile{ID: 2, LoginName: "b"})

	got := diff(sent, next, nil)
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

	cfg := &types.Config{DNSConfig: types.DNSConfig{BaseDomain: "example.com"}}

	want, err := peer.TailNode(capVer, func(types.NodeID) []netip.Prefix { return routes }, cfg, cfg.DNSView(), nil)
	if err != nil {
		t.Fatal(err)
	}

	base, err := (&peerRenders{}).render(cfg, cfg.DNSView(), capVer, 1, 1, peer, nil)
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

// Ported from the state package, where the comparator lived before it
// moved to the peer render.
func TestPeerHostinfoEqual(t *testing.T) {
	base := func() *tailcfg.Hostinfo {
		return &tailcfg.Hostinfo{
			Hostname:    "node",
			OS:          "linux",
			DeviceModel: "laptop",
			NetInfo:     &tailcfg.NetInfo{PreferredDERP: 1, WorkingUDP: opt.NewBool(true)},
		}
	}

	tests := []struct {
		name   string
		mutate func(*tailcfg.Hostinfo)
		want   bool
	}{
		{name: "no change", mutate: func(*tailcfg.Hostinfo) {}, want: true},
		{name: "device model", mutate: func(hi *tailcfg.Hostinfo) { hi.DeviceModel = "desktop" }, want: true},
		{name: "shields up", mutate: func(hi *tailcfg.Hostinfo) { hi.ShieldsUp = true }, want: true},
		{name: "ipn version", mutate: func(hi *tailcfg.Hostinfo) { hi.IPNVersion = "1.99" }, want: true},
		{name: "netinfo udp", mutate: func(hi *tailcfg.Hostinfo) { hi.NetInfo.WorkingUDP = opt.NewBool(false) }, want: true},
		{name: "netinfo dropped", mutate: func(hi *tailcfg.Hostinfo) { hi.NetInfo = nil }, want: true},
		{name: "hostname", mutate: func(hi *tailcfg.Hostinfo) { hi.Hostname = "other" }, want: false},
		{name: "os", mutate: func(hi *tailcfg.Hostinfo) { hi.OS = "windows" }, want: false},
		{
			name:   "services",
			mutate: func(hi *tailcfg.Hostinfo) { hi.Services = []tailcfg.Service{{Proto: "peerapi4", Port: 1}} },
			want:   false,
		},
		{name: "ssh host keys", mutate: func(hi *tailcfg.Hostinfo) { hi.SSH_HostKeys = []string{"ssh-ed25519 AAAA"} }, want: false},
		{name: "location", mutate: func(hi *tailcfg.Hostinfo) { hi.Location = &tailcfg.Location{Priority: 5} }, want: false},
		{name: "app connector", mutate: func(hi *tailcfg.Hostinfo) { hi.AppConnector = opt.NewBool(true) }, want: false},
		{
			name:   "routes",
			mutate: func(hi *tailcfg.Hostinfo) { hi.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")} },
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := base()
			tt.mutate(changed)
			require.Equal(t, tt.want, peerHostinfoEqual(base().View(), changed.View()))
		})
	}

	require.True(t, peerHostinfoEqual(tailcfg.HostinfoView{}, tailcfg.HostinfoView{}))
	require.False(t, peerHostinfoEqual(tailcfg.HostinfoView{}, base().View()))
}

// TestPeerHostinfoEqualSeesEveryField fails when tailscale adds a field to
// [tailcfg.Service] or [tailcfg.Location] that servicesEqual or locationEqual
// does not compare.
func TestPeerHostinfoEqualSeesEveryField(t *testing.T) {
	set := func(t *testing.T, f reflect.Value) {
		t.Helper()

		switch {
		case f.Kind() == reflect.String:
			f.SetString("x")
		case f.CanInt():
			f.SetInt(1)
		case f.CanUint():
			f.SetUint(1)
		case f.CanFloat():
			f.SetFloat(1)
		default:
			t.Fatalf("field kind %s not handled; compare it", f.Kind())
		}
	}

	for _, field := range reflect.VisibleFields(reflect.TypeFor[tailcfg.Service]()) {
		if !field.IsExported() {
			continue
		}

		t.Run("Service."+field.Name, func(t *testing.T) {
			var svc tailcfg.Service
			set(t, reflect.ValueOf(&svc).Elem().FieldByIndex(field.Index))

			a := &tailcfg.Hostinfo{Services: []tailcfg.Service{{}}}
			b := &tailcfg.Hostinfo{Services: []tailcfg.Service{svc}}
			assert.False(t, peerHostinfoEqual(a.View(), b.View()))
		})
	}

	for _, field := range reflect.VisibleFields(reflect.TypeFor[tailcfg.Location]()) {
		t.Run("Location."+field.Name, func(t *testing.T) {
			var loc tailcfg.Location
			set(t, reflect.ValueOf(&loc).Elem().FieldByIndex(field.Index))

			a := &tailcfg.Hostinfo{Location: &tailcfg.Location{}}
			b := &tailcfg.Hostinfo{Location: &loc}
			assert.False(t, peerHostinfoEqual(a.View(), b.View()))
		})
	}
}

func TestDiffClearsPeerCapabilitiesOnWire(t *testing.T) {
	before := testPeer(2)
	before.CapMap = tailcfg.NodeCapMap{"example.com/cap": {}}
	after := cloneNode(before)
	after.CapMap = nil
	responses := diff(testNetMap(before), testNetMap(after), nil)
	require.Len(t, responses, 1)
	data, err := Marshal(responses[0])
	require.NoError(t, err)

	var received tailcfg.MapResponse
	require.NoError(t, json.Unmarshal(data, &received))
	// A complete changed peer clears capabilities even when omitempty drops CapMap.
	require.Len(t, received.PeersChanged, 1)
	require.Equal(t, after.ID, received.PeersChanged[0].ID)
	require.Empty(t, received.PeersChanged[0].CapMap)
	require.Empty(t, received.PeersChangedPatch)
}

func TestDiffClearsPeerEndpointsOnWire(t *testing.T) {
	before := testPeer(2)
	after := cloneNode(before)
	after.Endpoints = nil
	responses := diff(testNetMap(before), testNetMap(after), nil)
	require.Len(t, responses, 1)
	data, err := Marshal(responses[0])
	require.NoError(t, err)

	var received tailcfg.MapResponse
	require.NoError(t, json.Unmarshal(data, &received))
	// The client converts PeersChanged to a patch, which also loses a nil clear.
	require.Len(t, received.Peers, 1)
	require.Empty(t, received.Peers[0].Endpoints)
	require.Empty(t, received.PeersChanged)
	require.Empty(t, received.PeersChangedPatch)
}

// TestPatchSendsExpiryInUTC pins that a patch carries the expiry in UTC.
// The database's zone can put the latest accepted expiry past year 9999,
// which encoding refuses for the whole response.
func TestPatchSendsExpiryInUTC(t *testing.T) {
	latest := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	loaded := latest.In(time.FixedZone("", 60*60))

	uid := uint(1)
	v4 := netip.MustParseAddr("100.64.0.7")
	node := &types.Node{
		ID:         7,
		GivenName:  "peer",
		Hostname:   "peer",
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		IPv4:       &v4,
		UserID:     &uid,
		User:       &types.User{Name: "u"},
		Hostinfo:   &tailcfg.Hostinfo{Hostname: "peer"},
	}
	cfg := &types.Config{DNSConfig: types.DNSConfig{BaseDomain: "example.com"}}

	before, err := (&peerRenders{}).render(cfg, cfg.DNSView(), capVer, 1, 1, node.View(), nil)
	require.NoError(t, err)

	// A relogin rotates the key and sets the expiry.
	node.NodeKey = key.NewNode().Public()
	node.Expiry = &loaded

	after, err := (&peerRenders{}).render(cfg, cfg.DNSView(), capVer, 2, 1, node.View(), nil)
	require.NoError(t, err)

	responses := diff(testNetMap(before), testNetMap(after), nil)
	require.Len(t, responses, 1)
	require.Len(t, responses[0].PeersChangedPatch, 1)

	_, err = Marshal(responses[0])
	require.NoError(t, err)
	assert.True(t, latest.Equal(*responses[0].PeersChangedPatch[0].KeyExpiry))
}

func TestModelCapMapCanonicalizationPreservesKeysAndPayloads(t *testing.T) {
	original := testNetMap(testPeer(2))
	original.peers = peerMapOf(&tailcfg.Node{ID: 2, CapMap: tailcfg.NodeCapMap{"present": nil, "payload": {tailcfg.RawMessage(`{"value":1}`)}}})
	client := newModelClient(fullResponse(&types.Config{}, original))
	client.apply(&tailcfg.MapResponse{PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 2, CapMap: tailcfg.NodeCapMap{"present": nil, "payload": {tailcfg.RawMessage(`{"value":1}`)}}}}})

	fresh := newModelClient(fullResponse(&types.Config{}, original))
	require.Empty(t, client.sameAs(fresh), "nil and empty presence-only payloads use Node.Clone's full-map representation")
	client.apply(&tailcfg.MapResponse{PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 2, CapMap: tailcfg.NodeCapMap{"payload": {tailcfg.RawMessage(`{"value":1}`)}}}}})
	require.NotEmpty(t, client.sameAs(fresh), "a missing capability key must still fail convergence")
	client.apply(&tailcfg.MapResponse{PeersChangedPatch: []*tailcfg.PeerChange{{NodeID: 2, CapMap: tailcfg.NodeCapMap{"present": nil, "payload": {tailcfg.RawMessage(`{"value":2}`)}}}}})
	require.NotEmpty(t, client.sameAs(fresh), "changed nonempty payloads must still fail convergence")
}

func TestDiffExpiryRemovalUsesWholePeerOnWire(t *testing.T) {
	before := testPeer(2)
	before.KeyExpiry = time.Now().Add(time.Hour).UTC()
	after := before.Clone()
	after.Key = key.NewNode().Public()
	after.KeyExpiry = time.Time{}
	sent := testNetMap(before)
	next := withPeers(sent, after)
	out := diff(sent, next, &frameCache{})
	require.Len(t, out, 1)
	require.Empty(t, out[0].PeersChangedPatch, "zero expiry is omitted from PeerChange even through a nonnil time pointer")
	require.Len(t, out[0].PeersChanged, 1)
	encoded, err := Marshal(out[0])
	require.NoError(t, err)
	require.NotContains(t, string(encoded), "KeyExpiry", "the complete peer must clear expiry even when omitted on the wire")

	var decoded tailcfg.MapResponse
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	require.Equal(t, after.Key, decoded.PeersChanged[0].Key)
	require.True(t, decoded.PeersChanged[0].KeyExpiry.IsZero())

	client := newModelClient(fullResponse(&types.Config{}, sent))
	client.apply(&decoded)
	require.True(t, client.peers[after.ID].KeyExpiry.IsZero())
	require.Equal(t, after.Key, client.peers[after.ID].Key)
	require.Empty(t, client.sameAs(newModelClient(fullResponse(&types.Config{}, next))))
}

// saasDiscoRotation retains the original S2.2 input-control and captured
// response assertions alongside the graph diff table that supersedes the event.
func saasDiscoRotation(t *testing.T) (bool, bool) {
	t.Helper()

	c, err := testcapture.Read(filepath.Join("..", "servertest", "testdata", "steps", "map-delivery.hujson"))
	require.NoError(t, err)

	id := c.NodeIDs["laptop"]

	var last *tailcfg.MapRequest

	for _, step := range c.Steps {
		if step.Name != "S2.2" {
			for _, f := range step.Frames["laptop"] {
				if f.Request != nil {
					last = f.Request
				}
			}

			continue
		}

		// The rotation's first report changes the disco key and nothing
		// else this row looks at.
		first := step.Frames["laptop"][0].Request
		require.NotNil(t, first, "S2.2 starts with laptop's report")
		require.NotNil(t, last, "laptop reported before S2.2")
		require.NotEqual(t, last.DiscoKey, first.DiscoKey, "disco key rotated")
		require.Equal(t, last.Endpoints, first.Endpoints, "endpoints kept")
		require.Equal(t, last.Hostinfo.NetInfo.PreferredDERP, first.Hostinfo.NetInfo.PreferredDERP, "DERP home kept")

		for _, f := range step.Frames["bystander"] {
			if f.Response == nil {
				continue
			}

			for _, n := range f.Response.PeersChanged {
				if n.ID == id {
					return !n.Key.IsZero() && n.DiscoKey == first.DiscoKey, len(n.Endpoints) > 0
				}
			}

			for _, p := range f.Response.PeersChangedPatch {
				if p.NodeID == id {
					return p.Key != nil && p.DiscoKey != nil, p.Endpoints != nil
				}
			}
		}
	}

	t.Fatal("no disco rotation reached bystander")

	return false, false
}

func wirePeer(id tailcfg.NodeID) *tailcfg.Node {
	raw := bytes.Repeat([]byte{byte(id)}, 32)                                                         //nolint:gosec // test IDs are 1..5
	addresses := []netip.Prefix{netip.PrefixFrom(netip.AddrFrom4([4]byte{100, 64, 0, byte(id)}), 32)} //nolint:gosec // test IDs are 1..5

	return &tailcfg.Node{
		ID: id, StableID: tailcfg.StableNodeID(fmt.Sprint(id)), Name: fmt.Sprintf("peer-%d.example.", id),
		User: 1, Key: key.NodePublicFromRaw32(mem.B(raw)),
		DiscoKey:  key.DiscoPublicFromRaw32(mem.B(raw)),
		Addresses: addresses, AllowedIPs: slices.Clone(addresses),
		Online: new(true), Cap: tailcfg.CurrentCapabilityVersion,
		Hostinfo: (&tailcfg.Hostinfo{Hostname: "peer", OS: "linux"}).View(),
	}
}

func wireText(t *rapid.T) string {
	return rapid.SampledFrom([]string{"", "plain", "quote\"slash\\\n\t", "<>&", "é\u96ea😀", "e\u0301\u2028\u2029", "\x00"}).Draw(t, "text")
}

func wireTime(t *rapid.T) *time.Time {
	switch rapid.IntRange(0, 3).Draw(t, "time-kind") {
	case 0:
		return nil
	case 1:
		return new(time.Time)
	default:
		return new(time.Unix(rapid.Int64Range(1, 4102444800).Draw(t, "seconds"), 123).UTC())
	}
}

func wireCaps(t *rapid.T) tailcfg.NodeCapMap {
	switch rapid.IntRange(0, 4).Draw(t, "caps-kind") {
	case 0:
		return nil
	case 1:
		return tailcfg.NodeCapMap{}
	case 2:
		return tailcfg.NodeCapMap{nodecap.FileSharing: nil}
	case 3:
		return tailcfg.NodeCapMap{nodecap.FileSharing: {}}
	default:
		payload, err := json.Marshal(wireText(t))
		require.NoError(t, err)

		return tailcfg.NodeCapMap{nodecap.FileSharing: {tailcfg.RawMessage(payload)}}
	}
}

func wireEdit(t *rapid.T, n *tailcfg.Node) {
	switch rapid.IntRange(0, 8).Draw(t, "field") {
	case 0:
		n.HomeDERP = tailcfg.DERPRegionID(rapid.IntRange(0, 3).Draw(t, "derp"))
	case 1:
		n.Endpoints = rapid.SampledFrom([][]netip.AddrPort{
			nil, {}, {netip.MustParseAddrPort("192.0.2.1:41641")}, {netip.MustParseAddrPort("[2001:db8::1]:1")},
		}).Draw(t, "endpoints")
	case 2:
		// Registered nodes have a nonzero public key; zero-key clears are
		// a separate generic PeerChange contract, not a valid registration.
		raw := bytes.Repeat([]byte{rapid.ByteRange(1, 255).Draw(t, "key-byte")}, 32)
		n.Key = key.NodePublicFromRaw32(mem.B(raw))

		n.DiscoKey = key.DiscoPublic{}
		if !rapid.Bool().Draw(t, "clear-disco") {
			n.DiscoKey = key.DiscoPublicFromRaw32(mem.B(raw))
		}
	case 3:
		n.KeyExpiry = time.Time{}
		if rapid.Bool().Draw(t, "expires") {
			n.KeyExpiry = time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
		}
	case 4:
		n.Online = new(rapid.Bool().Draw(t, "online"))

		n.LastSeen = nil
		if !*n.Online {
			n.LastSeen = new(time.Unix(rapid.Int64Range(1, 10000).Draw(t, "seen"), 0).UTC())
		}
	case 5:
		// A viewer can see an exit node's suggestion without receiving its
		// exit routes when policy grants only access to the node itself.
		n.CapMap = rapid.SampledFrom([]tailcfg.NodeCapMap{nil, {}, {nodecap.SuggestExitNode: nil}}).Draw(t, "peer-caps")
	case 6:
		n.Name = rapid.SampledFrom([]string{"peer.example.", "renamed.example."}).Draw(t, "name")
		n.Hostinfo = (&tailcfg.Hostinfo{Hostname: n.Name, OS: "linux"}).View()
	case 7:
		n.AllowedIPs = slices.Clone(n.Addresses)

		n.PrimaryRoutes = nil
		if rapid.Bool().Draw(t, "route") {
			n.PrimaryRoutes = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
			n.AllowedIPs = append(n.AllowedIPs, n.PrimaryRoutes...)
		}
	case 8:
		// A re-render with identical fields is a no-op even with new pointers.
	}
}

// TestRapidWireDiffReplay checks that serialized diffs converge on a fresh map.
// These are renderable peer fields: node keys stay nonzero, disco keys can clear,
// and peer capabilities use SuggestExitNode. The client may see that capability
// without exit routes when policy grants only access to the peer itself.
// This diagnostic property intentionally exposes current zero-disco and mixed
// offline/clear bugs; TestWireReachableFailures pins their State-to-wire paths.
func TestRapidWireDiffReplay(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sent := &netMap{self: wirePeer(1), peers: peerMapOf(), profiles: newProfileMap()}
		client := wirePeers{}
		hub := NewHub()
		steps := rapid.IntRange(1, 30).Draw(t, "steps")
		history := make([]*netMap, 1, steps+1)
		history[0] = sent
		retained := make([]any, 1, steps+1)

		retained[0] = wireJSON(t, sortedPeers(sent))
		for step := range steps {
			next := *sent
			next.at = time.Unix(int64(step+1), 0).UTC()
			e := sent.peers.Edit()

			for range rapid.IntRange(1, 3).Draw(t, "operations") {
				id := tailcfg.NodeID(rapid.IntRange(2, 5).Draw(t, "id"))
				switch rapid.IntRange(0, 3).Draw(t, "operation") {
				case 0:
					e.Delete(id)
				case 1:
					old := history[rapid.IntRange(0, len(history)-1).Draw(t, "restore")]
					if p, ok := old.peer(id); ok {
						e.Set(id, p)
					}
				default:
					p, ok := e.Get(id)
					if !ok {
						p = wirePeer(id)
					}

					p = p.Clone()
					for range rapid.IntRange(1, 3).Draw(t, "edits") {
						wireEdit(t, p)
					}

					e.Set(id, p)
				}
			}

			next.peers = e.Done()

			uncached := diff(sent, &next, nil)
			for repeat := range 2 {
				cached := diff(sent, &next, &hub.frames)
				require.Equal(t, wireJSON(t, uncached), wireJSON(t, cached), "cached diff, repeat %d", repeat)

				for _, resp := range cached {
					shared := hub.frames.share(resp)
					wireRoundTrip(t, hub, shared, false)
					decoded := wireRoundTrip(t, hub, shared, true)

					if repeat == 0 {
						client.apply(decoded)
					}
				}
			}

			fresh := wirePeers{}
			fresh.apply(wireDecode(t, &tailcfg.MapResponse{Peers: sortedPeers(&next)}))
			require.Equal(t, wireSemantic(t, fresh), wireSemantic(t, client), "step %d", step)

			sent = &next
			history = append(history, sent)
			retained = append(retained, wireJSON(t, sortedPeers(sent)))
		}

		for i, old := range history {
			require.Equal(t, retained[i], wireJSON(t, sortedPeers(old)), "retained render %d", i)
		}
	})
}

// Marshal's contract is encoding/json.Marshal, including omission and escaping.
// Reuse immutable node pointers across different responses to exercise nodeJSON.
func TestRapidWireMarshal(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := wirePeer(2)
		n.Name = wireText(t)
		n.Hostinfo = (&tailcfg.Hostinfo{Hostname: wireText(t), OS: wireText(t)}).View()

		n.LastSeen = wireTime(t)
		if expiry := wireTime(t); expiry != nil {
			n.KeyExpiry = *expiry
		}

		n.CapMap = wireCaps(t)
		n.KeySignature = rapid.SampledFrom([][]byte{nil, {}, {0}, {0, 255, 1}}).Draw(t, "signature")

		p := &tailcfg.PeerChange{NodeID: n.ID, CapMap: wireCaps(t), LastSeen: wireTime(t), KeyExpiry: wireTime(t), KeySignature: n.KeySignature}
		for repeat := range 3 {
			resp := &tailcfg.MapResponse{
				Node: n, Peers: []*tailcfg.Node{n}, PeersChanged: []*tailcfg.Node{n}, PeersChangedPatch: []*tailcfg.PeerChange{p},
				Domain: wireText(t), ControlTime: wireTime(t),
				DNSConfig:     &tailcfg.DNSConfig{Domains: []string{wireText(t)}},
				PacketFilters: rapid.SampledFrom([]map[string][]tailcfg.FilterRule{nil, {}, {"base": nil}, {"base": {}}, {"base": {{SrcIPs: []string{"*"}}}}}).Draw(t, "filters"),
				UserProfiles:  []tailcfg.UserProfile{{ID: 1, LoginName: wireText(t), DisplayName: wireText(t)}},
			}
			want := wireJSON(t, resp)
			data, err := Marshal(resp)
			require.NoError(t, err)

			var got any
			require.NoError(t, json.Unmarshal(data, &got))
			require.Equal(t, want, got, "Marshal repeat %d", repeat)

			var buf bytes.Buffer
			require.NoError(t, MarshalTo(&buf, resp))
			require.NoError(t, json.Unmarshal(buf.Bytes(), &got))
			require.Equal(t, want, got, "MarshalTo repeat %d", repeat)
			// Warming the cache must not change the source response.
			require.Equal(t, want, wireJSON(t, resp))
		}
	})
}

type wireFailWriter struct {
	remaining int
	err       error
}

func (w *wireFailWriter) Write(p []byte) (int, error) {
	if len(p) > w.remaining {
		n := w.remaining
		w.remaining = 0

		return n, w.err
	}

	w.remaining -= len(p)

	return len(p), nil
}

func TestRapidWireMarshalWriterError(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := wirePeer(2)
		n.Name = wireText(t)
		resp := &tailcfg.MapResponse{Peers: []*tailcfg.Node{n, n}}
		data, err := Marshal(resp)
		require.NoError(t, err)

		failure := io.ErrClosedPipe
		w := &wireFailWriter{remaining: rapid.IntRange(0, len(data)-1).Draw(t, "fail-after"), err: failure}
		require.ErrorIs(t, MarshalTo(w, resp), failure)
		// A failed write must not poison the shared node encoding.
		var buf bytes.Buffer
		require.NoError(t, MarshalTo(&buf, resp))
		require.JSONEq(t, string(data), buf.String())
	})
}

func TestRapidWireConnectivityReplay(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		before := wirePeer(2)
		client := wirePeers{}
		client.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{before}}))

		for range rapid.IntRange(1, 30).Draw(t, "steps") {
			after := before.Clone()
			after.Online = new(rapid.Bool().Draw(t, "online"))

			after.LastSeen = nil
			if !*after.Online {
				after.LastSeen = new(time.Unix(rapid.Int64Range(1, 10000).Draw(t, "seen"), 0).UTC())
			}

			sent := &netMap{peers: peerMapOf(before), profiles: newProfileMap()}

			next := withPeers(sent, after)
			for _, resp := range diff(sent, next, nil) {
				client.apply(wireDecode(t, resp))
			}

			fresh := wirePeers{}
			fresh.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{after}}))
			require.Equal(t, wireSemantic(t, fresh), wireSemantic(t, client))

			before = after
		}
	})
}

// These include documented generic peerPatch fields that Headscale does not
// currently render (Cap=0, Online=nil and nonempty KeySignature). A clear that
// requires a full list must still deliver concurrent removals and other edits.
func TestRapidWireClearWithRemoval(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		before := wirePeer(2)
		before.HomeDERP = 1
		before.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
		after := before.Clone()

		switch rapid.IntRange(0, 3).Draw(t, "clear") {
		case 0:
			after.HomeDERP = 0
		case 1:
			after.Endpoints = rapid.SampledFrom([][]netip.AddrPort{nil, {}}).Draw(t, "empty-endpoints")
		case 2:
			after.Cap = 0
		case 3:
			after.Online = nil
		}

		other := wirePeer(3)
		changed := other.Clone()
		changed.HomeDERP = tailcfg.DERPRegionID(rapid.IntRange(1, 10).Draw(t, "other-derp"))
		changed.KeySignature = rapid.SliceOfN(rapid.Byte(), 1, 20).Draw(t, "signature")
		sent := &netMap{peers: peerMapOf(before, other, wirePeer(4)), profiles: newProfileMap()}
		next := withPeers(sent, after, changed)
		client := wirePeers{}
		client.apply(wireDecode(t, &tailcfg.MapResponse{Peers: sortedPeers(sent)}))
		responses := diff(sent, next, nil)
		require.NotEmpty(t, responses)
		// Old clients require removals before a response forcing a rebuild.
		require.Equal(t, []tailcfg.NodeID{4}, responses[0].PeersRemoved)
		require.Empty(t, responses[0].Peers)

		for _, resp := range responses {
			client.apply(wireDecode(t, resp))
		}

		fresh := wirePeers{}
		fresh.apply(wireDecode(t, &tailcfg.MapResponse{Peers: sortedPeers(next)}))
		require.Equal(t, wireSemantic(t, fresh), wireSemantic(t, client))
	})
}

func TestRapidWirePeerPatch(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		before := wirePeer(2)
		before.KeySignature = []byte{1}
		after := before.Clone()
		after.Cap = tailcfg.CapabilityVersion(rapid.IntRange(1, 200).Draw(t, "cap"))
		after.KeySignature = rapid.SliceOfN(rapid.Byte(), 1, 20).Draw(t, "signature")
		after.CapMap = tailcfg.NodeCapMap{nodecap.FileSharing: nil}
		after.HomeDERP = tailcfg.DERPRegionID(rapid.IntRange(1, 10).Draw(t, "derp"))

		after.Online = new(rapid.Bool().Draw(t, "online"))
		if !*after.Online {
			after.LastSeen = new(time.Unix(1, 0).UTC())
		}

		patch, ok := peerPatch(before, after)
		require.True(t, ok)

		client := wirePeers{}
		client.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{before}}))
		client.apply(wireDecode(t, &tailcfg.MapResponse{PeersChangedPatch: []*tailcfg.PeerChange{patch}}))

		fresh := wirePeers{}
		fresh.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{after}}))
		require.Equal(t, wireSemantic(t, fresh), wireSemantic(t, client))
	})
}

// These tests use State, real renderers and streams. They intentionally assert
// the desired convergence and fail until the wire bugs are fixed.
func TestWireReachableFailures(t *testing.T) {
	for _, scenario := range []string{"disco-key-zero", "expiry-clear-offline", "capmap-clear-offline"} {
		t.Run(scenario, func(t *testing.T) {
			policy := `{"grants":[{"src":["u1@"],"dst":["u2@"],"ip":["*"]}]}`
			cfg, s, ids := streamTestState(t, policy)
			target := ids[2]
			before, ok := s.GetNodeByID(target)
			require.True(t, ok)

			var disco key.DiscoPublic
			require.NoError(t, disco.UnmarshalText([]byte("discokey:0101010101010101010101010101010101010101010101010101010101010101")))

			req := tailcfg.MapRequest{NodeKey: before.NodeKey(), DiscoKey: disco}
			if scenario == "capmap-clear-offline" {
				req.Hostinfo = &tailcfg.Hostinfo{Hostname: before.Hostname()}
				req.Hostinfo.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
			}

			require.NoError(t, s.UpdateNodeFromMapRequest(target, req))

			if scenario == "capmap-clear-offline" {
				_, err := s.SetApprovedRoutes(target, req.Hostinfo.RoutableIPs)
				require.NoError(t, err)
			}

			if scenario == "expiry-clear-offline" {
				_, err := s.SetNodeExpiry(target, new(time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)))
				require.NoError(t, err)
			}

			epoch := s.Connect(target)
			stream := NewStream(cfg, NewHub(), ids[0], capVer)
			initial, err := stream.Initial(s.Snapshot())
			require.NoError(t, err)

			client := wirePeers{}
			for _, resp := range initial {
				client.apply(wireDecode(t, resp))
			}

			require.Contains(t, client, target.NodeID())
			require.True(t, *client[target.NodeID()].Online)

			if scenario == "capmap-clear-offline" {
				require.Contains(t, client[target.NodeID()].CapMap, nodecap.SuggestExitNode)
				require.Equal(t, client[target.NodeID()].Addresses, client[target.NodeID()].AllowedIPs, "viewer has no Internet access")
			}

			switch scenario {
			case "disco-key-zero":
				req.DiscoKey = key.DiscoPublic{}
				require.NoError(t, s.UpdateNodeFromMapRequest(target, req))
				stored, ok := s.GetNodeByID(target)
				require.True(t, ok)
				require.True(t, stored.DiscoKey().IsZero(), "zero disco key reaches State")
				tn, err := stored.TailNode(capVer, s.GetNodePrimaryRoutes, cfg, s.Snapshot().DNS(), nil)
				require.NoError(t, err)
				require.True(t, tn.DiscoKey.IsZero(), "zero disco key reaches TailNode")
			case "expiry-clear-offline":
				_, err := s.SetNodeExpiry(target, nil)
				require.NoError(t, err)
				require.NoError(t, s.Disconnect(target, epoch))
			case "capmap-clear-offline":
				_, err := s.SetApprovedRoutes(target, nil)
				require.NoError(t, err)
				require.NoError(t, s.Disconnect(target, epoch))
			}

			updates, err := stream.Update(s.Snapshot())
			require.NoError(t, err)

			for _, resp := range updates {
				data, err := Marshal(resp)
				require.NoError(t, err)
				t.Logf("wire: %s", data)
				client.apply(wireDecode(t, resp))
			}

			fresh := wirePeers{}
			freshStream := NewStream(cfg, NewHub(), ids[0], capVer)
			freshResponses, err := freshStream.Initial(s.Snapshot())
			require.NoError(t, err)

			for _, resp := range freshResponses {
				fresh.apply(wireDecode(t, resp))
			}

			require.Equal(t, wireSemantic(t, fresh), wireSemantic(t, client))
		})
	}
}

// wirePeers models the peer state in Tailscale f7c1b8e52600's
// control/controlclient/map.go: upgradeNode, peerChangeDiff and
// updatePeersStateFromResponse. In particular, PeersChanged is NOT always
// replacement: the client first converts eligible entries to in-memory patches.
// Keep this independent of peerPatch, needsPeerListRefresh and modelClient.
type wirePeers map[tailcfg.NodeID]*tailcfg.Node

func (peers wirePeers) apply(resp *tailcfg.MapResponse) {
	if len(resp.Peers) > 0 {
		clear(peers)

		for _, n := range resp.Peers {
			peers[n.ID] = wireUpgrade(n)
		}

		return
	}

	// Patchification happens before removal in the client.
	patches := slices.Clone(resp.PeersChangedPatch)

	var replacements []*tailcfg.Node

	for _, n := range resp.PeersChanged {
		n = wireUpgrade(n)
		if before := peers[n.ID]; before != nil && wirePatchable(before, n) {
			p := &tailcfg.PeerChange{
				NodeID: n.ID, DERPRegion: n.HomeDERP, Cap: n.Cap,
				Endpoints: n.Endpoints, Key: &n.Key, DiscoKey: &n.DiscoKey,
				KeyExpiry: &n.KeyExpiry, KeySignature: n.KeySignature,
				CapMap: n.CapMap,
			}
			// An internal patch can clear a map or a zero expiry: it never
			// passes through JSON's omitempty/omitzero a second time.
			if p.CapMap == nil {
				p.CapMap = tailcfg.NodeCapMap{}
			}

			if before.Online != nil && n.Online != nil {
				p.Online = n.Online
			}

			if before.LastSeen != nil && n.LastSeen != nil {
				p.LastSeen = n.LastSeen
			}

			patches = append(patches, p)
		} else {
			replacements = append(replacements, n)
		}
	}

	for _, id := range resp.PeersRemoved {
		delete(peers, id)
	}

	for _, n := range replacements {
		peers[n.ID] = n
	}

	for _, p := range patches {
		n := peers[p.NodeID]
		if n == nil {
			continue
		}

		if p.DERPRegion != 0 {
			n.HomeDERP = p.DERPRegion
		}

		if p.Cap != 0 {
			n.Cap = p.Cap
		}

		if p.Endpoints != nil {
			n.Endpoints = p.Endpoints
		}

		if p.Key != nil {
			n.Key = *p.Key
		}

		if p.DiscoKey != nil {
			n.DiscoKey = *p.DiscoKey
		}

		if p.Online != nil {
			n.Online = p.Online
		}

		if p.LastSeen != nil {
			n.LastSeen = p.LastSeen
		}

		if p.KeyExpiry != nil {
			n.KeyExpiry = *p.KeyExpiry
		}

		if p.KeySignature != nil {
			n.KeySignature = p.KeySignature
		}

		if p.CapMap != nil {
			n.CapMap = p.CapMap
		}
	}
}

func wireUpgrade(n *tailcfg.Node) *tailcfg.Node {
	n = n.Clone()
	if n.AllowedIPs == nil {
		n.AllowedIPs = slices.Clone(n.Addresses)
	}

	return n
}

// All fields outside upstream's patch/ignored sets must compare equal.
// Reflection makes a future Node field conservative instead of dropping it.
// Generated nodes use modern HomeDERP and no legacy DERP string.
func wirePatchable(before, after *tailcfg.Node) bool {
	a, b := reflect.ValueOf(*before), reflect.ValueOf(*after)
	for field := range a.Type().Fields() {
		switch field.Name {
		case "Key", "DiscoKey", "KeyExpiry", "KeySignature", "HomeDERP", "Endpoints", "Cap", "CapMap", "Online", "LastSeen",
			"ComputedName", "ComputedNameWithHost", "computedHostIfDifferent", "DataPlaneAuditLogID", "StableTailnetID", "Capabilities":
			continue
		case "Hostinfo":
			if !before.Hostinfo.Equal(after.Hostinfo) {
				return false
			}
		case "Created":
			if !before.Created.Equal(after.Created) {
				return false
			}
		default:
			x, y := a.FieldByIndex(field.Index), b.FieldByIndex(field.Index)
			if x.Kind() == reflect.Slice && x.Len() == 0 && y.Len() == 0 {
				continue
			}

			if !reflect.DeepEqual(x.Interface(), y.Interface()) {
				return false
			}
		}
	}

	return true
}

func wireDecode(t require.TestingT, resp *tailcfg.MapResponse) *tailcfg.MapResponse {
	return wireRoundTrip(t, nil, resp, false)
}

// wireRoundTrip shares the real session Hub's encoded-frame cache when supplied.
// Standalone model inputs use the same encoder without a Hub cache.
func wireRoundTrip(t require.TestingT, hub *Hub, resp *tailcfg.MapResponse, compress bool) *tailcfg.MapResponse {
	var (
		data []byte
		err  error
	)
	if hub == nil {
		data, err = benchEncode(resp, compress)
	} else {
		data, err = hub.Encode(resp, compress, benchEncode)
	}

	require.NoError(t, err)

	if compress {
		data, err = zstdframe.AppendDecode(nil, data)
		require.NoError(t, err)
	}

	standard, err := json.Marshal(resp)
	require.NoError(t, err)
	require.JSONEq(t, string(standard), string(data), "Hub encoding changed response content")

	var decoded tailcfg.MapResponse
	require.NoError(t, json.Unmarshal(data, &decoded))

	return &decoded
}

func wireJSON(t require.TestingT, v any) any {
	data, err := json.Marshal(v)
	require.NoError(t, err)

	var decoded any
	require.NoError(t, json.Unmarshal(data, &decoded))

	return decoded
}

func wireSemantic(t require.TestingT, peers wirePeers) any {
	cloned := make(wirePeers, len(peers))
	for id, n := range peers {
		n = n.Clone()
		// tailcfg.Node documents LastSeen as stale while Online is true.
		if n.Online != nil && *n.Online {
			n.LastSeen = nil
		}

		cloned[id] = n
	}

	return wireJSON(t, cloned)
}

// propertyClient composes pinned peer replay with the sticky global fields and
// an observer that only learns removals through explicit delta frames.
type propertyClient struct {
	domain          string
	collectServices bool
	filters         map[string][]tailcfg.FilterRule
	self            *tailcfg.Node
	peers           wirePeers
	filter          []tailcfg.FilterRule
	ssh             *tailcfg.SSHPolicy
	dns             *tailcfg.DNSConfig
	derp            *tailcfg.DERPMap
	profiles        map[tailcfg.UserID]tailcfg.UserProfile
	seen            map[tailcfg.UserID]bool
	deltaPeers      map[tailcfg.NodeID]bool
}

func newPropertyClient(full *tailcfg.MapResponse) *propertyClient {
	c := &propertyClient{peers: wirePeers{}, filters: map[string][]tailcfg.FilterRule{}, profiles: map[tailcfg.UserID]tailcfg.UserProfile{}, seen: map[tailcfg.UserID]bool{}, deltaPeers: map[tailcfg.NodeID]bool{}}
	c.apply(full)

	return c
}

func (c *propertyClient) apply(r *tailcfg.MapResponse) {
	if r.Node != nil {
		c.self = wireUpgrade(r.Node)

		c.seen[c.self.User] = true
		if len(c.self.Tags) > 0 {
			c.seen[tailcfg.UserID(types.TaggedDevicesUserID)] = true
		}
	}

	if r.SSHPolicy != nil {
		c.ssh = r.SSHPolicy
	}

	if r.DNSConfig != nil {
		c.dns = r.DNSConfig
	}

	if r.DERPMap != nil {
		dm := r.DERPMap.Clone()
		// The pinned client treats omitted DERP fields as unchanged.
		if previous := c.derp; previous != nil {
			if dm.Regions == nil {
				dm.Regions, dm.OmitDefaultRegions = previous.Regions, previous.OmitDefaultRegions
			}

			if dm.HomeParams == nil {
				dm.HomeParams = previous.HomeParams
			} else if previous.HomeParams != nil && dm.HomeParams.RegionScore == nil {
				dm.HomeParams.RegionScore = previous.HomeParams.RegionScore
			}
		}

		c.derp = dm
	}

	if r.Domain != "" {
		c.domain = r.Domain
	}

	if value, ok := r.CollectServices.Get(); ok {
		c.collectServices = value
	}

	if r.PacketFilter != nil {
		c.filters["base"] = r.PacketFilter
	}

	if value, reset := r.PacketFilters["*"]; reset && value == nil {
		clear(c.filters)
	}

	for name, rules := range r.PacketFilters {
		if name == "*" {
			continue
		}

		if rules == nil {
			delete(c.filters, name)
		} else {
			c.filters[name] = rules
		}
	}

	c.filter = nil
	for _, name := range slices.Sorted(maps.Keys(c.filters)) {
		c.filter = append(c.filter, c.filters[name]...)
	}

	for _, p := range r.UserProfiles {
		c.profiles[p.ID] = p
	}

	for _, p := range slices.Concat(r.Peers, r.PeersChanged) {
		c.deltaPeers[p.ID] = true
	}

	for _, id := range r.PeersRemoved {
		delete(c.deltaPeers, id)
	}

	c.peers.apply(r)

	for _, p := range c.peers {
		c.seen[p.User] = true
	}
}

func (c *propertyClient) unseenProfile() tailcfg.UserID {
	for id := range c.profiles {
		if !c.seen[id] {
			return id
		}
	}

	return 0
}

func (c *propertyClient) check(t require.TestingT, fresh *propertyClient) {
	require.Equal(t, fresh.domain, c.domain, "domain")
	require.Equal(t, fresh.collectServices, c.collectServices, "service collection")
	require.Equal(t, wireSemantic(t, wirePeers{0: fresh.self}), wireSemantic(t, wirePeers{0: c.self}), "self")
	require.Equal(t, wireSemantic(t, fresh.peers), wireSemantic(t, c.peers), "peers")
	require.Equal(t, wireJSON(t, fresh.filter), wireJSON(t, c.filter), "filter")
	require.Equal(t, wireJSON(t, fresh.ssh), wireJSON(t, c.ssh), "SSH")
	require.Equal(t, wireJSON(t, fresh.dns), wireJSON(t, c.dns), "DNS")
	require.Equal(t, wireJSON(t, fresh.derp), wireJSON(t, c.derp), "DERP")

	for id, p := range fresh.profiles {
		require.Equal(t, p, c.profiles[id], "profile %d", id)
	}

	require.Zero(t, c.unseenProfile(), "hidden owner profile")
	require.Len(t, c.deltaPeers, len(fresh.peers), "delta-only observer retained a removed peer")

	for id := range fresh.peers {
		require.True(t, c.deltaPeers[id], "delta-only observer missed peer %d", id)
	}
}

func TestPropertyClientContracts(t *testing.T) {
	before := wirePeer(2)
	client := newPropertyClient(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{before, wirePeer(3)}}))
	// An empty full-list field is a delta, not a reset, in the pinned client.
	client.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{}}))
	require.Len(t, client.peers, 2)
	client.apply(wireDecode(t, &tailcfg.MapResponse{Peers: []*tailcfg.Node{before}}))
	require.Len(t, client.peers, 1)
	require.True(t, client.deltaPeers[3], "full replacement cannot notify delta-only observer")
	client.apply(&tailcfg.MapResponse{PeersRemoved: []tailcfg.NodeID{3}})
	require.NotContains(t, client.deltaPeers, tailcfg.NodeID(3))

	after := before.Clone()
	after.Online, after.LastSeen = new(false), new(propertyEpoch)
	client.apply(wireDecode(t, &tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{after}}))
	require.Nil(t, client.peers[2].LastSeen, "upstream patchification cannot introduce absent LastSeen")
	require.NotEqual(t, wireSemantic(t, wirePeers{2: after}), wireSemantic(t, client.peers), "offline lost fields must remain observable")
	after = after.Clone()
	after.Hostinfo = (&tailcfg.Hostinfo{Hostname: "changed"}).View()
	client.apply(wireDecode(t, &tailcfg.MapResponse{PeersChanged: []*tailcfg.Node{after}}))
	require.Equal(t, after.LastSeen, client.peers[2].LastSeen, "nonpatchable replacement keeps LastSeen")

	client.apply(&tailcfg.MapResponse{PacketFilters: map[string][]tailcfg.FilterRule{"a": {{SrcIPs: []string{"a"}}}, "b": {{SrcIPs: []string{"b"}}}}})
	require.Len(t, client.filter, 2)
	client.apply(&tailcfg.MapResponse{PacketFilters: map[string][]tailcfg.FilterRule{"a": nil}})
	require.Equal(t, "b", client.filter[0].SrcIPs[0])
	client.apply(&tailcfg.MapResponse{PacketFilters: map[string][]tailcfg.FilterRule{"*": nil}})
	require.Empty(t, client.filter)
}

func TestPropertyClientDERPStickyFields(t *testing.T) {
	initial := &tailcfg.DERPMap{
		Regions:            map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}},
		OmitDefaultRegions: true,
		HomeParams:         &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{1: 0.5}},
	}
	client := newPropertyClient(&tailcfg.MapResponse{DERPMap: initial})

	for _, update := range []*tailcfg.DERPMap{{}, {HomeParams: &tailcfg.DERPHomeParams{}}} {
		frozen := update.Clone()
		client.apply(&tailcfg.MapResponse{DERPMap: update})
		require.Equal(t, initial, client.derp, "nil fields retain previous values")
		require.Equal(t, frozen, update, "replay owns the received map")
	}

	client.apply(&tailcfg.MapResponse{DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}})
	require.Empty(t, client.derp.Regions)
	require.False(t, client.derp.OmitDefaultRegions, "non-nil Regions replaces the associated flag")
	require.Equal(t, initial.HomeParams, client.derp.HomeParams)

	scores := map[tailcfg.DERPRegionID]float64{2: 2}
	client.apply(&tailcfg.MapResponse{DERPMap: &tailcfg.DERPMap{HomeParams: &tailcfg.DERPHomeParams{RegionScore: scores}}})
	require.Equal(t, scores, client.derp.HomeParams.RegionScore)
	require.Empty(t, client.derp.Regions)
	require.False(t, client.derp.OmitDefaultRegions)
}

func TestPropertyWireEncodingSlots(t *testing.T) {
	hub := NewHub()
	defer hub.Close()

	response := hub.frames.share(&tailcfg.MapResponse{ControlTime: new(propertyEpoch), DERPMap: &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{1: {RegionID: 1}}}})
	require.Contains(t, hub.frames.byResp, response)

	for range 2 {
		for _, compress := range []bool{false, true} {
			wireRoundTrip(t, hub, response, compress)
		}
	}
}
