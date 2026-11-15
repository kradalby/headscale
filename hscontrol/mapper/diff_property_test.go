package mapper

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go4.org/mem"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
)

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
