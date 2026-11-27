package derp

import (
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// TestApplyPolicyFollowsKeyPrecedence holds [ApplyPolicy] to a plain
// reading of a policy's derpMap over drawn maps: a policy region replaces
// the configured one, null deletes it, OmitDefaultRegions keeps only the
// policy's, and HomeParams stay the configured ones. The captures hold the
// regions of the policies they cover; this holds HomeParams as well, every
// combination, and that neither input is written nor shared with the
// result, which outlives the policy it came from.
func TestApplyPolicyFollowsKeyPrecedence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		base, policy := drawDERPMap(t, false), drawDERPMap(t, true)
		for id, region := range base.Regions {
			require.Empty(t, ValidateRegion(id, region), "test sanity: a drawn configured region is valid")
		}

		if rapid.Bool().Draw(t, "nil configured map") {
			base = nil
		}

		baseBefore, policyBefore := base.Clone(), policy.Clone()
		want := policyPrecedence(base, policy)
		got := ApplyPolicy(base, policy)
		require.Equal(t, want, got, "policy precedence")
		require.Equal(t, baseBefore, base, "the configured map was written")
		require.Equal(t, policyBefore, policy, "the policy's map was written")

		_ = ApplyPolicy(base, drawDERPMap(t, true))
		require.Equal(t, want, got, "a later policy changed an earlier result")

		if base != nil && policy != nil {
			for _, region := range policy.Regions {
				if region != nil {
					region.Nodes[0].HostName = "changed.example.com"
				}
			}

			require.Equal(t, want, got, "the result shares the policy's regions")
		}
	})
}

// drawDERPMap draws a configured map of valid regions, or a policy's
// derpMap, which alone can be nil, delete a region with null, or omit the
// defaults. Policies may only add regions from 900 up.
func drawDERPMap(t *rapid.T, policy bool) *tailcfg.DERPMap {
	if policy && rapid.Bool().Draw(t, "nil policy map") {
		return nil
	}

	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
	custom := false

	for _, id := range []tailcfg.DERPRegionID{1, 2, 900, 999} {
		switch rapid.IntRange(0, 2).Draw(t, "region") {
		case 0:
			continue
		case 1:
			if policy {
				dm.Regions[id] = nil
				continue
			}
		}

		if policy && id < 900 {
			dm.Regions[id] = nil
			continue
		}

		version := rapid.IntRange(0, 2).Draw(t, "region version")
		dm.Regions[id] = &tailcfg.DERPRegion{
			RegionID: id, RegionCode: fmt.Sprintf("r%d", id), RegionName: fmt.Sprintf("region-%d-%d", id, version),
			Nodes: []*tailcfg.DERPNode{{Name: fmt.Sprintf("%da", id), RegionID: id, HostName: fmt.Sprintf("derp-%d-%d.example.com", id, version)}},
		}
		custom = true
	}

	if policy && custom {
		dm.OmitDefaultRegions = rapid.Bool().Draw(t, "omit default regions")
	}

	if policy && len(dm.Regions) == 0 && rapid.Bool().Draw(t, "nil regions") {
		dm.Regions = nil
	}

	switch rapid.IntRange(0, 3).Draw(t, "home params") {
	case 0:
	case 1:
		dm.HomeParams = &tailcfg.DERPHomeParams{}
		if !policy {
			dm.HomeParams.RegionScore = map[tailcfg.DERPRegionID]float64{}
		}
	default:
		dm.HomeParams = &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{}}

		for range rapid.IntRange(0, 4).Draw(t, "scores") {
			id := rapid.SampledFrom([]tailcfg.DERPRegionID{1, 2, 900, 999}).Draw(t, "scored region")
			dm.HomeParams.RegionScore[id] = rapid.SampledFrom([]float64{0.5, 1, 2}).Draw(t, "score")
		}
	}

	return dm
}

// policyPrecedence is the map a policy's derpMap makes of base, key by
// key, in storage of its own.
func policyPrecedence(base, policy *tailcfg.DERPMap) *tailcfg.DERPMap {
	if base == nil || policy == nil {
		return base.Clone()
	}

	out := &tailcfg.DERPMap{HomeParams: base.HomeParams.Clone(), Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}

	for _, id := range slices.AppendSeq(slices.Collect(maps.Keys(base.Regions)), maps.Keys(policy.Regions)) {
		region, named := policy.Regions[id]

		switch {
		case named:
		case policy.OmitDefaultRegions:
			continue
		default:
			region = base.Regions[id]
		}

		if region != nil {
			out.Regions[id] = region.Clone()
		}
	}

	return out
}
