package propcheck

import (
	"fmt"
	"maps"
	"slices"

	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

// DrawDERPMap draws complete configured maps or validated policy overlays.
// Only overlays allow nil maps, null deletions and OmitDefaultRegions.
func DrawDERPMap(t *rapid.T, policy bool) *tailcfg.DERPMap {
	if policy && rapid.Bool().Draw(t, "nil DERP policy") {
		return nil
	}

	dm := &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}
	custom := false

	for _, id := range []tailcfg.DERPRegionID{1, 2, 900, 999} {
		switch rapid.IntRange(0, 2).Draw(t, "DERP region choice") {
		case 0:
			continue
		case 1:
			if policy {
				dm.Regions[id] = nil
				continue
			}
		case 2:
		}

		if policy && id < 900 {
			dm.Regions[id] = nil
			continue
		}

		version := rapid.IntRange(0, 2).Draw(t, "DERP region version")
		dm.Regions[id] = &tailcfg.DERPRegion{
			RegionID: id, RegionCode: fmt.Sprintf("r%d", id), RegionName: fmt.Sprintf("region-%d-%d", id, version),
			Nodes: []*tailcfg.DERPNode{{Name: fmt.Sprintf("%da", id), RegionID: id, HostName: fmt.Sprintf("derp-%d-%d.example.com", id, version)}},
		}
		custom = true
	}

	if policy && custom {
		dm.OmitDefaultRegions = rapid.Bool().Draw(t, "omit default DERP regions")
	}

	if policy && len(dm.Regions) == 0 && rapid.Bool().Draw(t, "nil DERP regions") {
		dm.Regions = nil
	}

	switch rapid.IntRange(0, 3).Draw(t, "DERP home parameters") {
	case 0:
	case 1:
		dm.HomeParams = &tailcfg.DERPHomeParams{}
		if !policy {
			dm.HomeParams.RegionScore = map[tailcfg.DERPRegionID]float64{}
		}
	case 2, 3:
		dm.HomeParams = &tailcfg.DERPHomeParams{RegionScore: map[tailcfg.DERPRegionID]float64{}}

		for range rapid.IntRange(0, 4).Draw(t, "DERP score count") {
			id := rapid.SampledFrom([]tailcfg.DERPRegionID{1, 2, 900, 999}).Draw(t, "scored DERP region")
			dm.HomeParams.RegionScore[id] = rapid.SampledFrom([]float64{0.5, 1, 2}).Draw(t, "DERP score")
		}
	}

	return dm
}

// EffectiveDERP selects each key by policy precedence, independently of the
// production merge. Expected storage is owned; production may share base data.
func EffectiveDERP(base, policy *tailcfg.DERPMap) *tailcfg.DERPMap {
	if base == nil || policy == nil {
		return base.Clone()
	}

	out := &tailcfg.DERPMap{HomeParams: base.HomeParams.Clone(), Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}}

	ids := slices.AppendSeq(slices.Collect(maps.Keys(base.Regions)), maps.Keys(policy.Regions))
	for _, id := range ids {
		region, explicit := policy.Regions[id]
		switch {
		case explicit:
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
