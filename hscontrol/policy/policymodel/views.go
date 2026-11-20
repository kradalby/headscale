package policymodel

import (
	"slices"

	"tailscale.com/tailcfg"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// CompareUnder is [Compare] with each rule set built for a view of its
// own: ref as refView's client enforces it, cand as candView's. Two
// netmaps of one receiver, before and after a change that moved which
// capabilities nodes hold, are two views. The probes come from both rule
// sets and refView.
func CompareUnder(ref []tailcfg.FilterRule, refView ClientView, cand []tailcfg.FilterRule, candView ClientView) Report {
	var rep Report

	refM, err := filter.MatchesFromFilterRules(ref)
	if err != nil {
		rep.Parse = append(rep.Parse, "reference: "+err.Error())
	}

	candM, err := filter.MatchesFromFilterRules(cand)
	if err != nil {
		rep.Parse = append(rep.Parse, "candidate: "+err.Error())
	}

	refF := filter.New(refM, refView.HasCap, refView.LocalNets, nil, nil, logger.Discard)
	candF := filter.New(candM, candView.HasCap, candView.LocalNets, nil, nil, logger.Discard)

	space := newProbeSpace(slices.Concat(refM, candM), refView, false)

	for _, src := range space.srcs {
		for _, dst := range space.dsts {
			if src.Is4() != dst.Is4() {
				continue
			}

			rep.CapPairs++

			if rc, cc := refF.CapsWithValues(src, dst), candF.CapsWithValues(src, dst); !SamePeerCaps(rc, cc) {
				rep.Caps = append(rep.Caps, CapsDiff{Src: src, Dst: dst, Ref: rc, Cand: cc})
			}

			for _, proto := range space.protos {
				ports := []uint16{0}
				if HasPorts(proto) {
					ports = space.ports
				}

				for _, port := range ports {
					p := Probe{Proto: proto, Src: src, Dst: dst, Port: port}
					q := p.Packet()

					rep.Probes++

					if r, c := refF.RunIn(q, 0), candF.RunIn(q, 0); r != c {
						rep.Verdicts = append(rep.Verdicts, VerdictDiff{Probe: p, Ref: r, Cand: c})
					}
				}
			}
		}
	}

	return rep
}

// CompareViews is [CompareUnder] for one rule set under two views: what
// the views' difference alone changes.
func CompareViews(rules []tailcfg.FilterRule, a, b ClientView) Report {
	return CompareUnder(rules, a, rules, b)
}
