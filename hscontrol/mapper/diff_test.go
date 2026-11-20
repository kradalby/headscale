package mapper

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/key"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/types/views"
	"tailscale.com/wgengine/filter"
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

	base, err := (&peerRenders{}).render(cfg, cfg.DNSView(), capVer, 1, 1, peer, nil, false)
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

	before, err := (&peerRenders{}).render(cfg, cfg.DNSView(), capVer, 1, 1, node.View(), nil, false)
	require.NoError(t, err)

	// A relogin rotates the key and sets the expiry.
	node.NodeKey = key.NewNode().Public()
	node.Expiry = &loaded

	after, err := (&peerRenders{}).render(cfg, cfg.DNSView(), capVer, 2, 1, node.View(), nil, false)
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

// chunkDoc is the policy the chunk tests start from: rules of every kind a
// node is sent, ports, two protocols, an app capability each way (one with
// two values), own rules and autogroup:self.
const chunkDoc = `{"groups":{"group:a":["u1@"],"group:b":["u2@"]},"tagOwners":{"tag:t":["u1@"]},
	"grants":[
		{"src":["group:a"],"dst":["u2@"],"ip":["tcp:22"]},
		{"src":["group:b"],"dst":["u1@"],"ip":["tcp:80","udp:53"]},
		{"src":["u1@"],"dst":["u1@"],"ip":["tcp:443"]},
		{"src":["autogroup:member"],"dst":["autogroup:self"],"ip":["tcp:8080"]},
		{"src":["group:a"],"dst":["u2@"],"app":{"example.com/cap/x":[{"v":1},{"v":"second"}]}},
		{"src":["group:b"],"dst":["u1@"],"app":{"example.com/cap/y":[{"v":2}]}}
	]}`

// chunkSession is a stream and the client it writes to. The client keeps
// its chunks across map sessions, as tailscale-rs does; the Go client
// starts every map session holding none.
type chunkSession struct {
	id     types.NodeID
	st     *Stream
	client *modelClient
}

// chunkRun is a tailnet of sessions.
type chunkRun struct {
	t        *testing.T
	cfg      *types.Config
	s        *state.State
	hub      *Hub
	sessions map[types.NodeID]*chunkSession
	// switching is set while a render may change a session's delivery,
	// whose update then clears.
	switching bool
}

// open starts a stream for id, as a reconnect does: its first response
// goes to the client cs holds, or to a new one.
func (cr *chunkRun) open(id types.NodeID) *chunkSession {
	cr.t.Helper()

	cs := cr.sessions[id]
	if cs == nil {
		cs = &chunkSession{id: id, client: newModelClient(&tailcfg.MapResponse{})}
		cr.sessions[id] = cs
	}

	cs.st = NewStream(cr.cfg, cr.hub, id, capVer)

	resps, err := cs.st.Initial(cr.s.Snapshot())
	require.NoError(cr.t, err)
	cs.st.Delivered()

	f := resps[0].PacketFilters
	require.Contains(cr.t, f, "*", "a stream's first response clears what the client held")
	require.Nil(cr.t, f["*"])
	requireWireNulls(cr.t, resps[0])

	for _, r := range resps {
		cs.client.apply(r)
	}

	return cs
}

// render updates the sessions of ids, or all, to the current snapshot and
// requires each to hold what a fresh session is sent. It returns the
// PacketFilters each was sent.
func (cr *chunkRun) render(step string, ids ...types.NodeID) map[types.NodeID]map[string][]tailcfg.FilterRule {
	cr.t.Helper()

	if len(ids) == 0 {
		ids = slices.Sorted(maps.Keys(cr.sessions))
	}

	snap := cr.s.Snapshot()
	sent := make(map[types.NodeID]map[string][]tailcfg.FilterRule)

	for _, id := range ids {
		cs := cr.sessions[id]

		resps, err := cs.st.Update(snap)
		require.NoError(cr.t, err)
		cs.st.Delivered()

		for _, r := range resps {
			if r.PacketFilters != nil {
				_, cleared := r.PacketFilters["*"]
				require.Equalf(cr.t, cr.switching, cleared, "%s: node %d: a delta clears only when the delivery switches", step, id)
				requireWireNulls(cr.t, r)
				sent[id] = r.PacketFilters
			}

			cs.client.apply(r)
		}

		cr.requireFresh(step, cs)
	}

	return sent
}

// requireFresh requires cs's client to hold what a new session is sent.
func (cr *chunkRun) requireFresh(step string, cs *chunkSession) {
	cr.t.Helper()

	fresh, err := NewStream(cr.cfg, NewHub(), cs.id, capVer).Initial(cr.s.Snapshot())
	require.NoError(cr.t, err)

	require.Emptyf(cr.t, cs.client.sameAs(newModelClient(fresh[0])), "%s: node %d", step, cs.id)
}

// requireWireNulls requires every chunk resp deletes, and the clear, to be
// a literal null as the client reads it: an omitted or empty value would
// leave the chunk in force.
func requireWireNulls(t *testing.T, resp *tailcfg.MapResponse) {
	t.Helper()

	wire, err := Marshal(resp)
	require.NoError(t, err)

	for name, rules := range resp.PacketFilters {
		if rules == nil {
			require.Contains(t, string(wire), `"`+name+`":null`)
		}
	}

	var back tailcfg.MapResponse
	require.NoError(t, json.Unmarshal(wire, &back))
	require.Len(t, back.PacketFilters, len(resp.PacketFilters), "every chunk survives the wire")

	for name, rules := range resp.PacketFilters {
		got, ok := back.PacketFilters[name]
		require.True(t, ok)
		require.Equalf(t, rules == nil, got == nil, "chunk %q: null on one side only", name)
	}
}

// edits returns how update changed the chunks: names deleted, names sent.
func edits(update map[string][]tailcfg.FilterRule) ([]string, []string) {
	var gone, sent []string

	for name, rules := range update {
		if rules == nil {
			gone = append(gone, name)
		} else {
			sent = append(sent, name)
		}
	}

	slices.Sort(gone)
	slices.Sort(sent)

	return gone, sent
}

// TestStreamChunksConvergeToFresh drives sessions in capability mode, with
// filter chunks, through
// every way a node's filter moves and requires, after each, the client to
// hold exactly the chunks a new session is sent, and the update to carry
// only what moved: a rule removed, a port, a protocol, an app capability's
// value, rules reordered, the receiver's form flipping to addresses and
// back, the members of an address-form rule, the receiver's own address, a
// session that lags several commits, a failed render, a failed write and
// a reconnect.
func TestStreamChunksConvergeToFresh(t *testing.T) {
	t.Setenv(state.TestCapabilitySourcesEnv, "true")
	t.Setenv(state.TestFilterChunksEnv, "true")

	cfg, s, ids := streamTestState(t, chunkDoc)
	n1, n1b, n2 := ids[0], ids[1], ids[2]

	cr := &chunkRun{t: t, cfg: cfg, s: s, hub: NewHub(), sessions: map[types.NodeID]*chunkSession{}}
	for _, id := range ids {
		cr.open(id)
	}

	doc := chunkDoc
	edit := func(old, next string) {
		t.Helper()
		require.Contains(t, doc, old)
		doc = strings.Replace(doc, old, next, 1)

		_, err := s.SetPolicy([]byte(doc))
		require.NoError(t, err)
	}

	chunksOf := func(id types.NodeID) policyv2.FilterChunks { return cr.sessions[id].client.chunks }

	// A rule removed: its chunk deleted, nothing sent.
	before := chunksOf(n1)

	edit(`{"src":["u1@"],"dst":["u1@"],"ip":["tcp:443"]},`, "")

	gone, added := edits(cr.render("rule removed")[n1])
	require.Len(t, gone, 1)
	require.Empty(t, added)
	require.Equal(t, before.Len()-1, chunksOf(n1).Len())

	// A port edited: the old name deleted, the new one sent.
	edit(`"tcp:22"`, `"tcp:2222"`)

	gone, added = edits(cr.render("port edited")[n2])
	require.Len(t, gone, 1)
	require.Len(t, added, 1)

	// A protocol edited: tcp:80 and udp:53 become one rule.
	edit(`"udp:53"`, `"tcp:53"`)

	gone, added = edits(cr.render("protocol edited")[n1])
	require.Len(t, gone, 2)
	require.Len(t, added, 1)

	// An app capability's value: the CapGrant chunk again, nothing else.
	edit(`{"v":1}`, `{"v":3}`)

	gone, added = edits(cr.render("capability value edited")[n2])
	require.Len(t, gone, 1)
	require.Len(t, added, 1)
	require.True(t, strings.HasPrefix(added[0], "c/"), "the CapGrant chunk: %v", added)

	// Its second value alone: the CapGrant chunk again.
	edit(`{"v":"second"}`, `{"v":"2nd"}`)

	gone, added = edits(cr.render("second capability value edited")[n2])
	require.Len(t, gone, 1)
	require.Len(t, added, 1)

	// Only a protocol edited, and back: the rule is renamed each time.
	edit(`"tcp:2222"`, `"udp:2222"`)

	gone, added = edits(cr.render("only the protocol edited")[n2])
	require.Len(t, gone, 1)
	require.Len(t, added, 1)

	edit(`"udp:2222"`, `"tcp:2222"`)
	cr.render("protocol edited back")

	// Rules reordered: the same rules, under the same names.
	edit(`{"src":["group:a"],"dst":["u2@"],"ip":["tcp:2222"]},
		{"src":["group:b"],"dst":["u1@"],"ip":["tcp:80","tcp:53"]},`,
		`{"src":["group:b"],"dst":["u1@"],"ip":["tcp:80","tcp:53"]},
		{"src":["group:a"],"dst":["u2@"],"ip":["tcp:2222"]},`)
	require.Empty(t, cr.render("rules reordered"), "reordering rules sends no filter")

	// n2 announces a route: every rule it is sent goes as addresses, and
	// back. The CapGrant rule is addresses in both forms.
	announce := func(routes ...netip.Prefix) {
		t.Helper()

		node := mustNode(t, s, n2).AsStruct()
		hi := node.Hostinfo.Clone()
		hi.RoutableIPs = routes
		node.Hostinfo = hi
		s.PutNodeInStoreForTest(*node)
	}

	capChunk := func(c policyv2.FilterChunks) string {
		i := slices.IndexFunc(c.Names(), func(n string) bool { return strings.HasPrefix(n, "c/") })
		require.GreaterOrEqual(t, i, 0)

		return c.Names()[i]
	}

	capBefore := capChunk(chunksOf(n2))

	announce(netip.MustParsePrefix("10.9.0.0/24"))

	gone, added = edits(cr.render("form flips to addresses", n2)[n2])
	require.NotEmpty(t, gone)
	require.Len(t, added, len(gone))
	require.NotContains(t, gone, capBefore, "the CapGrant chunk is the same in both forms")

	addressForm := chunksOf(n2)

	// In address form, a member leaving group:a moves its two rules, the
	// port's and the app capability's, and no other.
	_, err := s.SetNodeTags(n1b, []string{"tag:t"})
	require.NoError(t, err)

	gone, added = edits(cr.render("member of an address-form rule left", n2)[n2])
	require.Len(t, gone, 2)
	require.Len(t, added, 2)
	require.Contains(t, gone, capChunk(addressForm))
	require.Equal(t, addressForm.Len(), chunksOf(n2).Len())

	announce()
	cr.render("form flips back")

	// n1's own address moves: every rule that reaches it is cut again.
	node := mustNode(t, s, n1).AsStruct()
	node.IPv4 = new(netip.MustParseAddr("100.64.0.99"))
	s.PutNodeInStoreForTest(*node)

	gone, added = edits(cr.render("own address moved", n1)[n1])
	require.NotEmpty(t, gone)
	require.NotEmpty(t, added)
	cr.render("own address moved, the others")

	// n2 lags three commits, then renders once.
	edit(`"tcp:2222"`, `"tcp:22"`)
	cr.render("lag 1", n1, n1b)
	edit(`{"v":3}`, `{"v":4}`)
	cr.render("lag 2", n1, n1b)
	edit(`"tcp:22"`, `"tcp:2200"`)
	cr.render("lag 3", n1, n1b)
	cr.render("lagging session renders", n2)

	// A render that fails leaves what the session holds: the next one
	// sends everything that moved since the last it sent. (A render fails
	// only before it reads the filter: a peer that cannot render is left
	// out instead.)
	broken := mustNode(t, s, n2).AsStruct()
	name := broken.GivenName
	broken.GivenName = strings.Repeat("a", types.MaxHostnameLength+1)
	s.PutNodeInStoreForTest(*broken)
	edit(`"tcp:2200"`, `"tcp:2201"`)

	_, err = cr.sessions[n2].st.Update(s.Snapshot())
	require.ErrorIs(t, err, types.ErrHostnameTooLong, "test sanity: its map cannot render")

	broken.GivenName = name
	s.PutNodeInStoreForTest(*broken)

	gone, added = edits(cr.render("after a failed render", n2)[n2])
	require.Len(t, gone, 1)
	require.Len(t, added, 1)
	cr.render("after a failed render, the others")

	// A write that fails ends the session: what it carried never reaches
	// the client, and the next session starts from a clear.
	edit(`"tcp:8080"`, `"tcp:8081"`)

	lost, err := cr.sessions[n1].st.Update(s.Snapshot())
	require.NoError(t, err)
	require.True(t, slices.ContainsFunc(lost, func(r *tailcfg.MapResponse) bool { return r.PacketFilters != nil }), "test sanity: the lost write carried the edit")

	cs := cr.open(n1)
	cr.requireFresh("reconnect after a failed write", cs)
	cr.render("after the reconnect")

	// A reconnect after a delivered edit: the client still holds what the
	// last session sent it.
	edit(`"tcp:80"`, `"tcp:81"`)
	cr.render("before the reconnect")
	cr.requireFresh("reconnect", cr.open(n2))
}

// TestFilterDeliveryCombinations pins what each combination of
// policy.capability_sources and policy.filter_chunks sends, and the
// per-client fallback: every first response clears; with chunks off the
// filter goes whole under "base", with chunks on as named chunks, in
// either source form; a node whose client is not Tailscale's (here
// tailscale-rs) is sent "base" either way; a session whose node's client
// changes is sent the whole state again, clear first. After every step
// each client holds what a new session is sent.
func TestFilterDeliveryCombinations(t *testing.T) {
	for _, capSources := range []bool{false, true} {
		for _, chunks := range []bool{false, true} {
			t.Run(fmt.Sprintf("capability_sources=%t/filter_chunks=%t", capSources, chunks), func(t *testing.T) {
				t.Setenv(state.TestCapabilitySourcesEnv, strconv.FormatBool(capSources))
				t.Setenv(state.TestFilterChunksEnv, strconv.FormatBool(chunks))

				cfg, s, ids := streamTestState(t, chunkDoc)
				n1, rust, n2 := ids[0], ids[1], ids[2]

				client := func(id types.NodeID, app string) {
					t.Helper()

					node := mustNode(t, s, id).AsStruct()
					node.Hostinfo = node.Hostinfo.Clone()
					node.Hostinfo.App = app
					s.PutNodeInStoreForTest(*node)
				}

				client(rust, "tailscale-rs")

				cr := &chunkRun{t: t, cfg: cfg, s: s, hub: NewHub(), sessions: map[types.NodeID]*chunkSession{}}

				// shape names what a response's filter is: "base" or chunks,
				// and whether a source is a capability.
				shape := func(f map[string][]tailcfg.FilterRule) (string, bool) {
					keys := slices.Sorted(maps.Keys(f))
					keys = slices.DeleteFunc(keys, func(k string) bool { return k == "*" })

					capForm := false

					for _, rules := range f {
						for _, r := range rules {
							capForm = capForm || slices.ContainsFunc(r.SrcIPs, func(src string) bool { return strings.HasPrefix(src, "cap:") })
						}
					}

					if slices.Equal(keys, []string{"base"}) {
						return "base", capForm
					}

					require.Truef(t, !slices.Contains(keys, "base") && len(keys) > 0, "chunks or base, not %v", keys)

					return "chunks", capForm
				}

				want := map[bool]string{false: "base", true: "chunks"}

				for _, id := range []types.NodeID{n1, rust, n2} {
					cs := cr.open(id)

					fresh, err := NewStream(cfg, NewHub(), id, capVer).Initial(s.Snapshot())
					require.NoError(t, err)

					got, capForm := shape(fresh[0].PacketFilters)
					wantShape := want[chunks]

					if id == rust {
						wantShape = "base"

						require.False(t, capForm, "tailscale-rs is sent addresses")
					} else {
						require.Equal(t, capSources, capForm, "node %d: the source form follows capability_sources alone", id)
					}

					require.Equalf(t, wantShape, got, "node %d's first response", id)
					require.Len(t, cs.client.chunks.Names(), len(policyv2.FilterChunks{}.ApplyResponse(fresh[0]).Names()))
				}

				// A port edited: chunks send the rule's change, base the whole
				// filter again; tailscale-rs is sent base.
				_, err := s.SetPolicy([]byte(strings.Replace(chunkDoc, `"tcp:80"`, `"tcp:8080"`, 1)))
				require.NoError(t, err)

				sent := cr.render("port edited")

				for _, id := range []types.NodeID{n1, rust} {
					f, ok := sent[id]
					require.Truef(t, ok, "node %d is sent the edit", id)

					got, _ := shape(f)
					if id == rust || !chunks {
						require.Equal(t, "base", got, "node %d", id)
					} else {
						gone, added := edits(f)
						require.NotEmpty(t, gone)
						require.NotEmpty(t, added)
					}
				}

				// n2's client turns into tailscale-rs and back: with chunks on,
				// each switch is the whole state again, clear first.
				cr.switching = chunks

				before := s.Snapshot()

				client(n2, "tailscale-rs")

				// Routing wakes n2 for it, though no map renders its client.
				after := s.Snapshot()
				if all, wake := Route(before, after, after.Since(before)); chunks && !all {
					require.Contains(t, wake, n2, "a node whose delivery moved is woken")
				}

				// Without chunks only the source form can move: tailscale-rs is
				// sent addresses.
				switched := cr.render("n2 reports tailscale-rs", n2)[n2]
				if chunks || capSources {
					got, capForm := shape(switched)
					require.Equal(t, "base", got)
					require.False(t, capForm)
				} else {
					require.Nil(t, switched, "base before and after, in address form: nothing to send")
				}

				client(n2, "")
				cr.render("n2 reports Tailscale again", n2)

				// Each field the decision reads, across the floor and back: the
				// client ends holding the whole filter, then chunks again, with
				// nothing of the other left.
				for _, tweak := range []struct {
					name string
					set  func(*tailcfg.Hostinfo)
				}{
					{"a release before the oldest served", func(hi *tailcfg.Hostinfo) { hi.IPNVersion = "1.0.0" }},
					{"a Go client reporting no release", func(hi *tailcfg.Hostinfo) { hi.IPNVersion = "" }},
					{"not built with Go", func(hi *tailcfg.Hostinfo) { hi.GoVersion = "" }},
				} {
					node := mustNode(t, s, n2).AsStruct()
					was := node.Hostinfo.Clone()
					node.Hostinfo = node.Hostinfo.Clone()
					tweak.set(node.Hostinfo)

					before := s.Snapshot()
					s.PutNodeInStoreForTest(*node)

					after := s.Snapshot()
					if all, wake := Route(before, after, after.Since(before)); chunks && !all {
						require.Contains(t, wake, n2, "%s: woken", tweak.name)
					}

					cr.render(tweak.name, n2)
					require.Equal(t, []string{"base"}, cr.sessions[n2].client.chunks.Names(), "%s: the client holds the whole filter alone", tweak.name)

					node = mustNode(t, s, n2).AsStruct()
					node.Hostinfo = was
					s.PutNodeInStoreForTest(*node)
					cr.render(tweak.name+", and back", n2)

					if chunks {
						require.NotContains(t, cr.sessions[n2].client.chunks.Names(), "base", "%s, and back: chunks again, base gone", tweak.name)
					}
				}

				cr.switching = false

				cr.render("all")
				cr.requireFresh("a reconnect of n2", cr.open(n2))
			})
		}
	}
}

// heldDivergence reports how the filter a client assembled from what it
// holds, held, answers otherwise than want, the compile's address form for
// the same node, through the client's own filter: every verdict from every
// node address and every address a rule names, to the node's addresses
// and every destination a rule names, on every port a rule names, by TCP,
// UDP, SCTP, ICMP and every protocol a rule names, and every app
// capability's values in order. caps answers capability sources as the
// client does from its netmap; local are the node's local nets. Neither
// the order of rules nor a rule held twice changes an answer, so it judges
// a chunked filter without going through the chunking. "" when they agree.
func heldDivergence(held, want []tailcfg.FilterRule, caps filter.CapTestFunc, local *netipx.IPSet, nodes views.Slice[types.NodeView]) string {
	build := func(rules []tailcfg.FilterRule) (*filter.Filter, error) {
		ms, err := filter.MatchesFromFilterRules(rules)
		if err != nil {
			return nil, err
		}

		return filter.New(ms, caps, local, nil, nil, logger.Discard), nil
	}

	got, err := build(held)
	if err != nil {
		return "held filter: " + err.Error()
	}

	ref, err := build(want)
	if err != nil {
		return "compile's filter: " + err.Error()
	}

	var srcs, dsts []netip.Addr

	ports := []uint16{0, 1, 65535}
	protos := []ipproto.Proto{ipproto.TCP, ipproto.UDP, ipproto.SCTP}

	// edges adds a rule entry's first and last address and the ones past
	// them; "*" and capabilities name no address.
	edges := func(out *[]netip.Addr, entry string) {
		r, err := util.ParseIPRange(entry)
		if err != nil {
			return
		}

		*out = append(*out, r.From(), r.To(), r.From().Prev(), r.To().Next())
	}

	for _, n := range nodes.All() {
		srcs = append(srcs, n.IPs()...)
	}

	for _, r := range local.Ranges() {
		dsts = append(dsts, r.From(), r.To())
	}

	for _, rule := range slices.Concat(held, want) {
		for _, s := range rule.SrcIPs {
			edges(&srcs, s)
		}

		for _, d := range rule.DstPorts {
			edges(&dsts, d.IP)
			ports = append(ports, d.Ports.First, d.Ports.Last, d.Ports.First-1, d.Ports.Last+1)
		}

		for _, g := range rule.CapGrant {
			for _, p := range g.Dsts {
				dsts = append(dsts, p.Masked().Addr())
			}
		}

		for _, p := range rule.IPProto {
			protos = append(protos, ipproto.Proto(p)) //nolint:gosec // protocol numbers fit
		}
	}

	srcs = append(srcs, netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1"))

	slices.SortFunc(srcs, netip.Addr.Compare)
	slices.SortFunc(dsts, netip.Addr.Compare)
	slices.Sort(ports)
	slices.Sort(protos)

	ports, protos = slices.Compact(ports), slices.Compact(protos)

	for _, src := range slices.Compact(srcs) {
		for _, dst := range slices.Compact(dsts) {
			if !src.IsValid() || !dst.IsValid() || src.Is4() != dst.Is4() {
				continue
			}

			if a, b := ref.CapsWithValues(src, dst), got.CapsWithValues(src, dst); !reflect.DeepEqual(a, b) {
				return fmt.Sprintf("caps %s -> %s: compile %v, held %v", src, dst, a, b)
			}

			icmp := ipproto.ICMPv4
			if src.Is6() {
				icmp = ipproto.ICMPv6
			}

			for _, proto := range append(slices.Clone(protos), icmp) {
				for _, port := range ports {
					if a, b := ref.Check(src, dst, port, proto), got.Check(src, dst, port, proto); a != b {
						return fmt.Sprintf("%s %s -> %s:%d: compile %v, held %v", proto, src, dst, port, a, b)
					}

					if proto != ipproto.TCP && proto != ipproto.UDP && proto != ipproto.SCTP {
						break
					}
				}
			}
		}
	}

	return ""
}

// clientLookup answers capability sources as a client holding c does: an
// address names the node, itself or a peer, holding it, the last in ID
// order when two do, and that node's CapMap answers.
func clientLookup(c *modelClient) filter.CapTestFunc {
	byAddr := map[netip.Addr]*tailcfg.Node{}

	nodes := slices.SortedFunc(maps.Values(c.peers), func(a, b *tailcfg.Node) int { return cmp.Compare(a.ID, b.ID) })
	if c.self != nil {
		nodes = append([]*tailcfg.Node{c.self}, nodes...)
	}

	for _, n := range nodes {
		for _, p := range n.Addresses {
			if p.IsSingleIP() {
				byAddr[p.Addr()] = n
			}
		}
	}

	return func(src netip.Addr, capability nodecap.Cap) bool {
		n, ok := byAddr[src]
		if !ok {
			return false
		}

		_, has := n.CapMap[capability]

		return has
	}
}

// localNets are a node's local nets as its client builds them: its own
// addresses, the routes it announces, and everything for an app connector.
func localNets(n types.NodeView) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, ip := range n.IPs() {
		b.Add(ip)
	}

	if hi := n.Hostinfo(); hi.Valid() {
		for _, p := range hi.RoutableIPs().All() {
			b.AddPrefix(p)
		}

		if hi.AppConnector().EqualBool(true) {
			b.AddPrefix(netip.MustParsePrefix("0.0.0.0/0"))
			b.AddPrefix(netip.MustParsePrefix("::/0"))
		}
	}

	set, _ := b.IPSet()

	return set
}

// TestNodeWithoutHostinfoRenders loads a node whose stored Hostinfo is
// NULL, as a row stored before its node reported one loads, and connects
// it: its own map and its peer's render, and routing the commit, with
// filter chunks off and on. A node with no Hostinfo reports no client and is
// sent the whole filter.
func TestNodeWithoutHostinfoRenders(t *testing.T) {
	for _, chunks := range []bool{false, true} {
		t.Run(fmt.Sprintf("filter_chunks=%t", chunks), func(t *testing.T) {
			t.Setenv(state.TestCapabilitySourcesEnv, "false")
			t.Setenv(state.TestFilterChunksEnv, strconv.FormatBool(chunks))

			p4 := netip.MustParsePrefix("100.64.0.0/10")
			p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
			cfg := &types.Config{
				Database:  types.DatabaseConfig{Type: types.DatabaseSqlite, Sqlite: types.SqliteConfig{Path: t.TempDir() + "/h.db"}},
				ServerURL: "https://headscale.test",
				Policy:    types.PolicyConfig{Mode: types.PolicyModeDB},
				Prefixes:  types.PrefixesConfig{V4: &p4, V6: &p6, Allocation: types.IPAllocationStrategySequential},
				DNSConfig: types.DNSConfig{BaseDomain: "headscale.test"},
			}

			database, err := db.NewHeadscaleDatabase(cfg)
			require.NoError(t, err)

			u := database.CreateUserForTest("u1")
			bare := database.CreateRegisteredNodeForTest(u, "bare")
			peer := database.CreateRegisteredNodeForTest(u, "peer")
			require.NoError(t, database.DB.Exec("UPDATE nodes SET host_info = NULL WHERE id = ?", bare.ID).Error)
			require.NoError(t, database.Close())

			s, err := state.NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			nv, ok := s.GetNodeByID(bare.ID)
			require.True(t, ok)
			require.False(t, nv.Hostinfo().Valid(), "test sanity: the node loads with no Hostinfo")

			hub := NewHub()

			streams := map[types.NodeID]*Stream{}
			for _, id := range []types.NodeID{bare.ID, peer.ID} {
				streams[id] = NewStream(cfg, hub, id, capVer)

				first, err := streams[id].Initial(s.Snapshot())
				require.NoError(t, err)

				_, whole := first[0].PacketFilters["base"]
				require.Equal(t, id == bare.ID || !chunks, whole, "node %d: a node reporting no client, and every node with chunks off, is sent the whole filter", id)
			}

			before := s.Snapshot()
			s.Connect(bare.ID)
			after := s.Snapshot()

			all, wake := Route(before, after, after.Since(before))
			require.True(t, all || len(wake) > 0, "test sanity: connecting wakes someone")

			for id, st := range streams {
				_, err := st.Update(after)
				require.NoError(t, err, "node %d", id)
			}
		})
	}
}
