package mapper

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
)

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
