package state

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

func TestHostinfoStructuralEqual(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		require.True(t, hostinfoStructuralEqual(nil, nil))
	})

	t.Run("one nil", func(t *testing.T) {
		require.False(t, hostinfoStructuralEqual(&tailcfg.Hostinfo{}, nil))
		require.False(t, hostinfoStructuralEqual(nil, &tailcfg.Hostinfo{}))
	})

	t.Run("identical", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1", OS: "linux"}
		b := &tailcfg.Hostinfo{Hostname: "node1", OS: "linux"}
		require.True(t, hostinfoStructuralEqual(a, b))
	})

	t.Run("DERPLatency jitter is not structural", func(t *testing.T) {
		a := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.010},
			},
		}
		b := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				DERPLatency:   map[string]float64{"1-v4": 0.025}, // jitter
			},
		}
		require.True(t, hostinfoStructuralEqual(a, b),
			"DERPLatency jitter must not be reported as structural change")
	})

	t.Run("PreferredDERP change is not structural", func(t *testing.T) {
		a := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 1},
		}
		b := &tailcfg.Hostinfo{
			Hostname: "node1",
			NetInfo:  &tailcfg.NetInfo{PreferredDERP: 2},
		}
		require.True(t, hostinfoStructuralEqual(a, b),
			"PreferredDERP change is tracked separately, not structural")
	})

	t.Run("hostname change is structural", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1"}
		b := &tailcfg.Hostinfo{Hostname: "node2"}
		require.False(t, hostinfoStructuralEqual(a, b))
	})

	t.Run("route change is structural", func(t *testing.T) {
		a := &tailcfg.Hostinfo{Hostname: "node1", RoutableIPs: nil}
		b := &tailcfg.Hostinfo{Hostname: "node1"}
		// RoutableIPs nil vs nil: equal
		require.True(t, hostinfoStructuralEqual(a, b))

		// Add a route: structural
		// (also tracked separately as routesChangedInput)
		b.RoutableIPs = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}
		require.False(t, hostinfoStructuralEqual(a, b))
	})
}

func TestNetInfoEqualIgnoringDERP(t *testing.T) {
	t.Run("both nil", func(t *testing.T) {
		require.True(t, netInfoEqualIgnoringDERP(nil, nil))
	})

	t.Run("ignores PreferredDERP", func(t *testing.T) {
		a := &tailcfg.NetInfo{PreferredDERP: 1, WorkingUDP: opt.NewBool(true)}
		b := &tailcfg.NetInfo{PreferredDERP: 9, WorkingUDP: opt.NewBool(true)}
		require.True(t, netInfoEqualIgnoringDERP(a, b))
	})

	t.Run("ignores DERPLatency", func(t *testing.T) {
		a := &tailcfg.NetInfo{DERPLatency: map[string]float64{"1": 0.01}}
		b := &tailcfg.NetInfo{DERPLatency: map[string]float64{"1": 0.99}}
		require.True(t, netInfoEqualIgnoringDERP(a, b))
	})

	t.Run("catches WorkingUDP change", func(t *testing.T) {
		a := &tailcfg.NetInfo{WorkingUDP: opt.NewBool(true)}
		b := &tailcfg.NetInfo{WorkingUDP: opt.NewBool(false)}
		require.False(t, netInfoEqualIgnoringDERP(a, b))
	})
}

func TestHostinfoDERP(t *testing.T) {
	require.Equal(t, 0, hostinfoDERP(nil))
	require.Equal(t, 0, hostinfoDERP(&tailcfg.Hostinfo{}))
	require.Equal(t, 0, hostinfoDERP(&tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{}}))
	require.Equal(t, 5, hostinfoDERP(&tailcfg.Hostinfo{NetInfo: &tailcfg.NetInfo{PreferredDERP: 5}}))
}
