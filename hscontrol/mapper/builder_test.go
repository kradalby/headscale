package mapper

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestStreamFullMapFields(t *testing.T) {
	cfg, s, ids := streamTestState(t, "", func(c *types.Config) { c.LogTail.Enabled = false })
	st := NewStream(cfg, NewHub(), ids[0], capVer)
	out, err := st.Initial(s.Snapshot())
	require.NoError(t, err)
	require.Len(t, out, 1)
	full := out[0]

	for _, tt := range []struct {
		name  string
		check func(*testing.T)
	}{
		{"TestMapResponseBuilder_Basic", func(t *testing.T) {
			t.Helper()
			require.NotNil(t, full)
			require.False(t, full.KeepAlive)
			require.NotNil(t, full.ControlTime)
			require.WithinDuration(t, time.Now(), *full.ControlTime, time.Second)
		}},
		{"TestMapResponseBuilder_WithCapabilityVersion", func(t *testing.T) {
			t.Helper()
			require.Equal(t, capVer, st.r.capVer)

			for _, peer := range full.Peers {
				require.Equal(t, capVer, peer.Cap)
			}
		}},
		{"TestMapResponseBuilder_WithDomain", func(t *testing.T) {
			t.Helper()
			require.Equal(t, "headscale.test", full.Domain)
		}},
		{"TestMapResponseBuilder_WithCollectServicesDisabled", func(t *testing.T) {
			t.Helper()

			value, set := full.CollectServices.Get()
			require.True(t, set)
			require.False(t, value)
		}},
		{"TestMapResponseBuilder_WithDebugConfig", func(t *testing.T) {
			t.Helper()
			require.Equal(t, &tailcfg.Debug{DisableLogTail: true}, full.Debug)
		}},
		{"TestMapResponseBuilder_ChainedCalls", func(t *testing.T) {
			t.Helper()
			require.NotNil(t, full.Node)
			require.NotNil(t, full.DERPMap)
			require.NotNil(t, full.SSHPolicy)
			require.NotNil(t, full.DNSConfig)
			require.NotNil(t, full.PacketFilters)
			require.NotEmpty(t, full.Peers)
			_, err := json.Marshal(full)
			require.NoError(t, err)
		}},
	} {
		t.Run(tt.name, tt.check)
	}
}

func TestStreamMissingNodeReturnsErrorWithoutFrames(t *testing.T) {
	cfg, s, _ := streamTestState(t, "")
	for _, id := range []types.NodeID{0, 999} {
		out, err := NewStream(cfg, NewHub(), id, capVer).Initial(s.Snapshot())
		require.ErrorIs(t, err, ErrNodeGone)
		require.Nil(t, out, "failed rendering must not write a partial map")
	}
}
