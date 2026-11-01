//go:build headscale_debug

package state

import (
	"cmp"
	"crypto/sha256"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// The explorer refuses larger scenes; keep Graph.elm's limits equal.
const (
	debugGraphVertexLimit = 200
	debugGraphEdgeLimit   = 1000
)

// DebugGraphQuery selects a bounded view of one snapshot.
type DebugGraphQuery struct {
	Perspective string
	Search      string
	Focus       string
}

// DebugGraphVertex is an explicitly selected, safe set of display properties.
type DebugGraphVertex struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	// Only core cells have exact change revisions; entity properties are diffed.
	ChangedAt  string            `json:"changedAt"`
	Properties map[string]string `json:"properties"`
}

// DebugGraphEdge names a directed relationship, not an ACL explanation.
type DebugGraphEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

// DebugGraphScene is a complete bounded scene. Counts refer to devices;
// Limit includes auxiliary vertices as well as devices.
type DebugGraphScene struct {
	Revision     string             `json:"revision"`
	Timestamp    string             `json:"timestamp"`
	Perspective  string             `json:"perspective"`
	Search       string             `json:"search"`
	Focus        string             `json:"focus"`
	Vertices     []DebugGraphVertex `json:"vertices"`
	Edges        []DebugGraphEdge   `json:"edges"`
	TotalNodes   int                `json:"totalNodes"`
	MatchedNodes int                `json:"matchedNodes"`
	ShownNodes   int                `json:"shownNodes"`
	Limit        int                `json:"limit"`
	Truncated    bool               `json:"truncated"`
	PolicyError  string             `json:"policyError"`
}

type debugGraphBuilder struct {
	scene    DebugGraphScene
	vertices map[string]DebugGraphVertex
	edges    map[string]DebugGraphEdge
}

func (b *debugGraphBuilder) vertex(v DebugGraphVertex) bool {
	if _, exists := b.vertices[v.ID]; exists {
		return true
	}

	if len(b.vertices) == debugGraphVertexLimit {
		b.scene.Truncated = true
		return false
	}

	if v.Properties == nil {
		v.Properties = map[string]string{}
	}

	b.vertices[v.ID] = v
	if v.Kind == "node" {
		b.scene.ShownNodes++
	}

	return true
}

func (b *debugGraphBuilder) edge(source, target, kind string) {
	if _, ok := b.vertices[source]; !ok {
		return
	}

	if _, ok := b.vertices[target]; !ok {
		return
	}

	id := url.QueryEscape(source) + "/" + url.QueryEscape(kind) + "/" + url.QueryEscape(target)
	if _, ok := b.edges[id]; ok {
		return
	}

	if len(b.edges) == debugGraphEdgeLimit {
		b.scene.Truncated = true
		return
	}

	b.edges[id] = DebugGraphEdge{ID: id, Source: source, Target: target, Kind: kind}
}

// DebugGraph reads only s, including metadata, policy, routes and peer visibility.
// World projections scan devices once per refresh; large installations should
// avoid live mode. Bounds limit the scene, not this O(N) matching scan.
func (s *Snapshot) DebugGraph(q DebugGraphQuery) DebugGraphScene {
	q.Perspective = cmp.Or(q.Perspective, "core")
	q.Search = strings.TrimSpace(q.Search)

	b := debugGraphBuilder{
		scene: DebugGraphScene{
			Revision: strconv.FormatUint(s.Rev(), 10), Timestamp: s.Time().UTC().Format(time.RFC3339Nano),
			Perspective: q.Perspective, Search: q.Search, Focus: q.Focus, Limit: debugGraphVertexLimit,
			TotalNodes: s.nodes().Len(), Vertices: []DebugGraphVertex{}, Edges: []DebugGraphEdge{},
		},
		vertices: make(map[string]DebugGraphVertex), edges: make(map[string]DebugGraphEdge),
	}

	err := s.PolicyErr()
	if err != nil {
		b.scene.PolicyError = err.Error()
	}

	cells := s.w.g.Inspect(s.s)
	for _, cell := range cells {
		b.vertex(s.debugGraphCell(cell))
	}

	for _, cell := range cells {
		for _, dep := range cell.Dependencies {
			b.edge("cell:"+cell.Name, "cell:"+dep, "depends on")
		}
	}

	if q.Perspective == "world" {
		b.edge("cell:policy", "cell:policy-source", "compiled from")
		s.debugGraphWorld(&b, q)
	}

	b.scene.Vertices = slices.SortedFunc(maps.Values(b.vertices), func(a, b DebugGraphVertex) int { return strings.Compare(a.ID, b.ID) })
	b.scene.Edges = slices.SortedFunc(maps.Values(b.edges), func(a, b DebugGraphEdge) int { return strings.Compare(a.ID, b.ID) })

	return b.scene
}

func (s *Snapshot) debugGraphCell(cell graph.CellInfo) DebugGraphVertex {
	props := map[string]string{"name": cell.Name, "dependencies": strings.Join(cell.Dependencies, ", ")}

	summary := cell.Kind + " cell"
	switch cell.Name {
	case "nodes", "index", "policy-nodes", "peers", "node-caps":
		summary = fmt.Sprintf("%d devices", s.nodes().Len())
	case "users", "policy-users":
		summary = fmt.Sprintf("%d users", len(s.Users()))
	case "policy-source":
		summary = fmt.Sprintf("%d bytes of source policy", len(s.PolicySource()))
	case "policy", "peer-policy":
		summary = "Compiled policy; source-rule tracing unavailable"
	case "primaries":
		summary = fmt.Sprintf("%d primary routes", len(s.PrimaryRoutes()))
	case "derp-map":
		count := 0
		if dm := s.DERPMap(); dm != nil {
			count = len(dm.Regions)
		}

		summary = fmt.Sprintf("%d configured regions; not active relay connections", count)
	case "dns":
		summary = fmt.Sprintf("%d extra DNS records", s.DNS().ExtraRecords().Len())
	}

	return DebugGraphVertex{
		ID: "cell:" + cell.Name, Label: cell.Name, Kind: cell.Kind, Summary: summary,
		ChangedAt: strconv.FormatUint(cell.ChangedAt, 10), Properties: props,
	}
}

func debugGraphNodeID(n types.NodeView) string { return "node:" + n.ID().String() }

func debugGraphNodeProperties(n types.NodeView) map[string]string {
	p := map[string]string{
		"id": n.ID().String(), "hostname": n.Hostname(), "name": n.GivenName(),
		"addresses": strings.Join(n.IPsAsString(), ", "), "online": strconv.FormatBool(n.Online()),
	}
	if n.IsTagged() {
		p["tags"] = strings.Join(n.Tags().AsSlice(), ", ")
	} else if owner := n.Owner(); owner.Valid() {
		p["owner"] = owner.Display()
		p["ownerID"] = strconv.FormatUint(uint64(owner.ID()), 10)
	}

	return p
}

func (s *Snapshot) debugGraphWorld(b *debugGraphBuilder, q DebugGraphQuery) {
	focusID, focused := debugGraphDeviceID(q.Focus)

	var peers []types.NodeID
	if focused {
		peers = s.PeerView(focusID)
	}

	search := strings.ToLower(q.Search)
	matched := func(n types.NodeView) bool {
		id := debugGraphNodeID(n)
		if search != "" {
			props := debugGraphNodeProperties(n)

			text := strings.Join([]string{id, props["hostname"], props["name"], props["addresses"], props["owner"], props["tags"]}, " ")
			if !n.IsTagged() {
				text += " " + n.Owner().Username()
			}

			if !strings.Contains(strings.ToLower(text), search) &&
				!slices.ContainsFunc(slices.Concat(n.AnnouncedRoutes(), n.ApprovedRoutes().AsSlice(), s.PrimaryRoutesForNode(n.ID())), func(p netip.Prefix) bool {
					return strings.Contains(p.String(), search)
				}) {
				return false
			}
		}

		if focused {
			_, visible := slices.BinarySearch(peers, n.ID())
			return n.ID() == focusID || visible
		}

		switch {
		case q.Focus == "", strings.HasPrefix(q.Focus, "cell:"):
			return q.Focus != "cell:derp-map" && q.Focus != "cell:dns"
		case strings.HasPrefix(q.Focus, "user:"):
			return !n.IsTagged() && n.Owner().Valid() && q.Focus == fmt.Sprintf("user:%d", n.Owner().ID())
		case strings.HasPrefix(q.Focus, "tag:"):
			return slices.Contains(n.Tags().AsSlice(), strings.TrimPrefix(q.Focus, "tag:"))
		case strings.HasPrefix(q.Focus, "route:"):
			return slices.ContainsFunc(slices.Concat(n.AnnouncedRoutes(), n.ApprovedRoutes().AsSlice(), s.PrimaryRoutesForNode(n.ID())), func(p netip.Prefix) bool {
				return q.Focus == "route:"+p.String()
			})
		}

		return false
	}
	// Put the focus first so a high-ID device cannot disappear behind the limit.
	if n, ok := s.GetNode(focusID); focused && ok && matched(n) {
		s.debugGraphAddNode(b, n, search)
	}

	for _, n := range s.ListNodes().All() {
		if !matched(n) {
			continue
		}

		b.scene.MatchedNodes++
		// Reserve the selected identity before its node's other relationships.
		switch {
		case strings.HasPrefix(q.Focus, "route:"):
			b.vertex(DebugGraphVertex{ID: q.Focus, Label: strings.TrimPrefix(q.Focus, "route:"), Kind: "route", Summary: "Route prefix", Properties: map[string]string{"prefix": strings.TrimPrefix(q.Focus, "route:")}})
		case strings.HasPrefix(q.Focus, "tag:"):
			b.vertex(DebugGraphVertex{ID: q.Focus, Label: strings.TrimPrefix(q.Focus, "tag:"), Kind: "tag", Summary: "Tag identity", Properties: map[string]string{"tag": strings.TrimPrefix(q.Focus, "tag:")}})
		case strings.HasPrefix(q.Focus, "user:"):
			b.vertex(s.debugGraphUser(n.Owner()))
		}

		if n.ID() == focusID && focused {
			continue
		}

		if len(b.vertices) == debugGraphVertexLimit {
			b.scene.Truncated = true
			continue
		}

		s.debugGraphAddNode(b, n, search)
	}

	if focused {
		// Only the selected device's shared peer view is expanded, never all pairs.
		for _, peer := range peers {
			if peer != focusID {
				b.edge("node:"+peer.String(), "node:"+focusID.String(), "visible to")
			}
		}
	}

	s.debugGraphValues(b, q, search)
}

func (s *Snapshot) debugGraphValues(b *debugGraphBuilder, q DebugGraphQuery, search string) {
	if slices.Contains([]string{"", "cell:users", "cell:policy-users"}, q.Focus) || strings.HasPrefix(q.Focus, "user:") {
		users := s.Users()
		for _, i := range slices.SortedFunc(slices.Values(users), func(a, b types.User) int { return cmp.Compare(a.ID, b.ID) }) {
			u := i.View()
			if strings.HasPrefix(q.Focus, "user:") && q.Focus != fmt.Sprintf("user:%d", u.ID()) {
				continue
			}

			if search != "" && !strings.Contains(strings.ToLower(u.Display()+" "+u.Name()+" "+u.Username()), search) {
				continue
			}

			if !b.vertex(s.debugGraphUser(u)) {
				break
			}

			b.edge("cell:users", fmt.Sprintf("user:%d", u.ID()), "contains")
		}
	}

	if q.Focus == "" || q.Focus == "cell:derp-map" || strings.HasPrefix(q.Focus, "derp:") {
		if dm := s.DERPMap(); dm != nil {
			for _, id := range slices.Sorted(maps.Keys(dm.Regions)) {
				r := dm.Regions[id]
				if r == nil {
					continue
				}

				v := s.debugGraphDERP(id, r)
				if search != "" && !strings.Contains(strings.ToLower(v.Label), search) {
					continue
				}

				if strings.HasPrefix(q.Focus, "derp:") && q.Focus != v.ID {
					continue
				}

				if !b.vertex(v) {
					break
				}

				b.edge("cell:derp-map", v.ID, "contains")
			}
		}
	}

	if q.Focus == "" || q.Focus == "cell:dns" || strings.HasPrefix(q.Focus, "dns:") {
		for _, r := range s.DNS().ExtraRecords().All() {
			v := s.debugGraphDNS(r)
			if search != "" && !strings.Contains(strings.ToLower(r.Name+" "+r.Value), search) {
				continue
			}

			if strings.HasPrefix(q.Focus, "dns:") && q.Focus != v.ID {
				continue
			}

			if !b.vertex(v) {
				break
			}

			b.edge("cell:dns", v.ID, "contains")
		}
	}
}

func (s *Snapshot) debugGraphAddNode(b *debugGraphBuilder, n types.NodeView, search string) {
	id := debugGraphNodeID(n)
	if !b.vertex(DebugGraphVertex{
		ID: id, Label: cmp.Or(n.GivenName(), n.Hostname(), id), Kind: "node",
		Summary: strings.Join(n.IPsAsString(), ", "), Properties: debugGraphNodeProperties(n),
	}) {
		return
	}

	b.edge("cell:nodes", id, "contains")

	routes := []struct {
		kind   string
		routes []netip.Prefix
	}{
		{"advertises", n.AnnouncedRoutes()},
		{"approved for", n.ApprovedRoutes().AsSlice()},
		{"primary for", s.PrimaryRoutesForNode(n.ID())},
	}
	addRoutes := func(matching bool) {
		for _, relation := range routes {
			for _, prefix := range relation.routes {
				label := prefix.String()
				if (search != "" && strings.Contains(label, search)) != matching {
					continue
				}

				routeID := "route:" + label
				if !b.vertex(DebugGraphVertex{ID: routeID, Label: label, Kind: "route", Summary: "Route prefix", Properties: map[string]string{"prefix": label}}) {
					continue
				}

				b.edge(id, routeID, relation.kind)
			}
		}
	}
	// Keep matching routes and their relations ahead of unrelated scene expansion.
	if search != "" {
		addRoutes(true)
	}

	filterID := "filter:" + n.ID().String()
	b.vertex(DebugGraphVertex{
		ID: filterID, Label: "Effective filter: " + n.GivenName(), Kind: "filter",
		Summary:    "Per-device packet filter and SSH policy; visibility is not an ACL",
		Properties: map[string]string{"node": id, "source": "cell:policy-source"},
	})
	b.edge(filterID, id, "effective filter for")
	b.edge(filterID, "cell:policy", "compiled from")

	if n.IsTagged() {
		for _, tag := range slices.Sorted(slices.Values(n.Tags().AsSlice())) {
			tagID := "tag:" + tag
			if !b.vertex(DebugGraphVertex{ID: tagID, Label: tag, Kind: "tag", Summary: "Tag identity", Properties: map[string]string{"tag": tag}}) {
				continue
			}

			b.edge(id, tagID, "tagged with")
		}
	} else if u := n.Owner(); u.Valid() {
		b.vertex(s.debugGraphUser(u))
		b.edge(id, fmt.Sprintf("user:%d", u.ID()), "owned by")
	}

	addRoutes(false)
}

func (s *Snapshot) debugGraphUser(u types.UserView) DebugGraphVertex {
	return DebugGraphVertex{
		ID: fmt.Sprintf("user:%d", u.ID()), Label: u.Display(), Kind: "user", Summary: "User identity",
		Properties: map[string]string{"id": strconv.FormatUint(uint64(u.ID()), 10), "name": u.Name(), "displayName": u.DisplayName()},
	}
}

func (s *Snapshot) debugGraphDERP(id tailcfg.DERPRegionID, r *tailcfg.DERPRegion) DebugGraphVertex {
	return DebugGraphVertex{
		ID: fmt.Sprintf("derp:%d", id), Label: r.RegionName, Kind: "derp",
		Summary:    "Configured region; not an active relay connection",
		Properties: map[string]string{"regionID": fmt.Sprint(id), "regionCode": r.RegionCode, "nodes": strconv.Itoa(len(r.Nodes))},
	}
}

func (s *Snapshot) debugGraphDNS(r tailcfg.DNSRecord) DebugGraphVertex {
	return DebugGraphVertex{
		ID:    fmt.Sprintf("dns:%x", sha256.Sum256([]byte(r.Name+"\x00"+r.Type+"\x00"+r.Value))),
		Label: r.Name, Kind: "dns", Summary: r.Type + " " + r.Value,
		Properties: map[string]string{"name": r.Name, "type": r.Type, "value": r.Value},
	}
}

func debugGraphDeviceID(id string) (types.NodeID, bool) {
	kind, value, ok := strings.Cut(id, ":")
	if !ok || (kind != "node" && kind != "filter") {
		return 0, false
	}

	n, err := strconv.ParseUint(value, 10, 64)

	return types.NodeID(n), err == nil && strconv.FormatUint(n, 10) == value
}

// DebugGraphDetail returns allowlisted details for id from this snapshot.
// The HTTP layer checks the requested revision before calling it.
// Packet filters remain complete: the HTTP layer rejects details over its
// response-size limit rather than silently displaying incomplete rules.
func (s *Snapshot) DebugGraphDetail(id, serverURL string) (any, bool) {
	if strings.HasPrefix(id, "derp:") {
		if dm := s.DERPMap(); dm != nil {
			for regionID, region := range dm.Regions {
				if region == nil || id != fmt.Sprintf("derp:%d", regionID) {
					continue
				}

				nodes := make([]map[string]string, 0, min(len(region.Nodes), debugGraphVertexLimit))
				for _, n := range region.Nodes {
					if n == nil {
						continue
					}

					if len(nodes) == debugGraphVertexLimit {
						break
					}

					nodes = append(nodes, map[string]string{"name": n.Name, "hostname": n.HostName, "derpPort": strconv.Itoa(n.DERPPort), "stunPort": strconv.Itoa(n.STUNPort)})
				}

				return map[string]any{
					"properties": s.debugGraphDERP(regionID, region).Properties, "nodes": nodes,
					"totalNodes": len(region.Nodes), "truncated": len(region.Nodes) > len(nodes),
				}, true
			}
		}

		return nil, false
	}

	if nid, ok := debugGraphDeviceID(id); ok {
		n, found := s.GetNode(nid)
		if !found {
			return nil, false
		}

		filter, filterErr := s.Policy().FilterForNode(n)
		ssh, sshErr := s.Policy().SSHPolicy(serverURL, n)
		props := debugGraphNodeProperties(n)

		props["os"], props["expiry"], props["lastSeen"] = "", "", ""
		if hostinfo := n.Hostinfo(); hostinfo.Valid() {
			props["os"] = hostinfo.OS()
		}

		if expiry := n.Expiry(); expiry.Valid() {
			props["expiry"] = expiry.Get().UTC().Format(time.RFC3339Nano)
		}

		if lastSeen := n.LastSeen(); lastSeen.Valid() {
			props["lastSeen"] = lastSeen.Get().UTC().Format(time.RFC3339Nano)
		}

		props["expired"] = strconv.FormatBool(n.IsExpiredAt(s.Time()))

		props["ephemeral"] = strconv.FormatBool(n.IsEphemeral())
		for name, routes := range map[string][]netip.Prefix{
			"announcedRoutes": n.AnnouncedRoutes(), "approvedRoutes": n.ApprovedRoutes().AsSlice(), "primaryRoutes": s.PrimaryRoutesForNode(n.ID()),
		} {
			prefixes := make([]string, 0, len(routes))
			for _, prefix := range routes {
				prefixes = append(prefixes, prefix.String())
			}

			props[name] = strings.Join(prefixes, ", ")
		}

		detail := map[string]any{
			"properties": props, "packetFilter": filter, "sshPolicy": ssh,
			"capabilities": s.Policy().NodeCapMaps()[nid], "policySource": "cell:policy-source",
		}
		if filterErr != nil {
			detail["filterError"] = filterErr.Error()
		}

		if sshErr != nil {
			detail["sshError"] = sshErr.Error()
		}

		return detail, true
	}

	if strings.HasPrefix(id, "cell:") {
		for _, cell := range s.w.g.Inspect(s.s) {
			if id != "cell:"+cell.Name {
				continue
			}

			detail := map[string]any{"cell": s.debugGraphCell(cell)}
			switch cell.Name {
			case "policy-source":
				detail["source"] = string(s.PolicySource())
			case "policy", "peer-policy":
				filter, _ := s.Policy().Filter()
				detail["packetFilter"] = filter
				detail["policySource"] = "cell:policy-source"
			default:
				detail["scene"] = s.DebugGraph(DebugGraphQuery{Perspective: "world", Focus: id})
			}

			return detail, true
		}

		return nil, false
	}

	for _, v := range s.DebugGraph(DebugGraphQuery{Perspective: "world", Focus: id}).Vertices {
		if v.ID == id {
			return v.Properties, true
		}
	}

	return nil, false
}
