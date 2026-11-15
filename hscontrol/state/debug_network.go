//go:build headscale_debug

package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/tailscale/hujson"
)

var errNetworkNodeMissing = errors.New("node not found")

var errNetworkPolicyUnavailable = errors.New("policy explanation unavailable")

var errNetworkSourceMissing = errors.New("source not found")

var errNetworkSourceIP = errors.New("sourceIP must belong to source node")

var errNetworkDestinationMissing = errors.New("destination not found")

var errNetworkSSHDestination = errors.New("SSH requires a destination node")

type NetworkQuery struct {
	OnlyPermitted                             bool
	Protocol                                  *int
	Port                                      *uint16
	Category, Search, Identity, ID, Direction string
	Offset, Limit                             int
}
type NetworkObject struct {
	MemberCount   int      `json:"memberCount"`
	ID            string   `json:"id"`
	Kind          string   `json:"kind"`
	Label         string   `json:"label"`
	NodeID        string   `json:"nodeId"`
	Addresses     []string `json:"addresses"`
	OwnerID       string   `json:"ownerId"`
	Tags          []string `json:"tags"`
	Online        *bool    `json:"online"`
	Expired       bool     `json:"expired"`
	RelatedIDs    []string `json:"relatedIds"`
	Provenance    string   `json:"provenance"`
	Protocol      string   `json:"protocol"`
	FirstPort     uint16   `json:"firstPort"`
	LastPort      uint16   `json:"lastPort"`
	Advertised    bool     `json:"advertised"`
	Approved      bool     `json:"approved"`
	Selected      bool     `json:"selected"`
	SourceVisible bool     `json:"sourceVisible"`
}
type NetworkPage struct {
	Revision   string          `json:"revision"`
	Timestamp  string          `json:"timestamp"`
	Category   string          `json:"category"`
	Total      int             `json:"total"`
	Matched    int             `json:"matched"`
	Offset     int             `json:"offset"`
	Limit      int             `json:"limit"`
	NextOffset *int            `json:"nextOffset"`
	Items      []NetworkObject `json:"items"`
}
type NetworkRelationship struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Kind   string `json:"kind"`
}
type NetworkTopology struct {
	Revision      string                `json:"revision"`
	Timestamp     string                `json:"timestamp"`
	Objects       []NetworkObject       `json:"objects"`
	Relationships []NetworkRelationship `json:"relationships"`
	Omitted       int                   `json:"omitted"`
	ObjectLimit   int                   `json:"objectLimit"`
	EdgeLimit     int                   `json:"edgeLimit"`
}

func networkObject(id, kind, label string) NetworkObject {
	return NetworkObject{ID: id, Kind: kind, Label: label, Addresses: []string{}, Tags: []string{}, RelatedIDs: []string{}}
}

func networkNode(n types.NodeView, now time.Time) NetworkObject {
	o := networkObject(fmt.Sprintf("node:%d", n.ID()), "node", n.GivenName())
	if o.Label == "" {
		o.Label = n.Hostname()
	}

	o.NodeID = fmt.Sprint(n.ID())
	o.Addresses = append(o.Addresses, n.IPsAsString()...)
	o.Tags = append(o.Tags, n.Tags().AsSlice()...)

	v, ok := n.IsOnline().GetOk()
	if ok {
		o.Online = new(v)
	}

	o.Expired = n.IsExpiredAt(now)
	if n.IsTagged() {
		for _, tag := range o.Tags {
			o.RelatedIDs = append(o.RelatedIDs, "tag:"+tag)
		}
	} else {
		o.OwnerID = fmt.Sprintf("user:%d", n.TypedUserID())
		o.RelatedIDs = append(o.RelatedIDs, o.OwnerID)
	}

	return o
}

func (s *Snapshot) networkObjects(category string, nodeIDs ...string) []NetworkObject {
	out := []NetworkObject{}

	if category == "users" {
		for _, u := range s.Users() {
			out = append(out, networkObject(fmt.Sprintf("user:%d", u.ID), "user", u.Name))
		}
	}

	tags := map[string]bool{}

	if category == "tags" {
		raw, err := hujson.Standardize(bytes.Clone(s.PolicySource()))
		if err == nil {
			var p struct {
				TagOwners map[string]json.RawMessage `json:"tagOwners"`
			}
			if json.Unmarshal(raw, &p) == nil {
				for tag := range p.TagOwners {
					tags[tag] = true
				}
			}
		}
	}

	for _, n := range s.ListNodes().All() {
		node := networkNode(n, s.Time())
		if len(nodeIDs) > 0 && !slices.Contains(nodeIDs, node.ID) {
			continue
		}

		switch category {
		case "nodes":
			out = append(out, node)
		case "tags":
			for _, tag := range n.Tags().All() {
				tags[tag] = true
			}
		case "routes":
			routes := slices.Concat(n.AnnouncedRoutes(), n.AllApprovedRoutes(), s.PrimaryRoutesForNode(n.ID()))
			slices.SortFunc(routes, netip.Prefix.Compare)

			for _, p := range slices.Compact(routes) {
				o := networkObject(fmt.Sprintf("route:%d:%s", n.ID(), p), "route", p.String())
				o.NodeID = node.NodeID
				o.RelatedIDs = append(o.RelatedIDs, node.ID)
				o.Advertised = slices.Contains(n.AnnouncedRoutes(), p)
				o.Approved = slices.Contains(n.AllApprovedRoutes(), p)
				id, ok := s.PrimaryRouteFor(p)
				o.Selected = ok && id == n.ID()
				out = append(out, o)
			}
		case "services":
			if n.Hostinfo().Valid() {
				for _, svc := range n.Hostinfo().Services().All() {
					o := networkObject(fmt.Sprintf("service:%d:host:%s:%d", n.ID(), svc.Proto, svc.Port), "service", fmt.Sprintf("%s:%d", svc.Proto, svc.Port))
					o.NodeID = node.NodeID
					o.RelatedIDs = append(o.RelatedIDs, node.ID)
					o.Provenance = "host-reported"
					o.Protocol = string(svc.Proto)
					o.FirstPort = svc.Port
					o.LastPort = svc.Port
					out = append(out, o)
				}
			}

			filter, err := s.Policy().FilterForNode(n)
			if err == nil {
				for i, f := range filter {
					for j, d := range f.DstPorts {
						o := networkObject(fmt.Sprintf("service:%d:policy:%d:%d", n.ID(), i, j), "service", fmt.Sprintf("%s:%d-%d", d.IP, d.Ports.First, d.Ports.Last))
						o.NodeID = node.NodeID
						o.RelatedIDs = append(o.RelatedIDs, node.ID)
						o.Provenance = "policy-endpoint"
						o.Protocol = fmt.Sprint(f.IPProto)
						o.FirstPort = d.Ports.First
						o.LastPort = d.Ports.Last
						out = append(out, o)
					}
				}
			}
		}
	}

	if category == "tags" {
		for tag := range tags {
			o := networkObject("tag:"+tag, "tag", tag)
			for _, u := range s.Users() {
				if s.Policy().UserCanHaveTag(u.View(), tag) {
					o.RelatedIDs = append(o.RelatedIDs, fmt.Sprintf("user:%d", u.ID))
				}
			}

			out = append(out, o)
		}
	}

	slices.SortFunc(out, func(a, b NetworkObject) int { return strings.Compare(a.ID, b.ID) })

	return out
}

func (s *Snapshot) DebugNetworkInventory(q NetworkQuery) NetworkPage {
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 50
	}

	if q.Offset < 0 {
		q.Offset = 0
	}

	all := s.networkObjects(q.Category)
	p := NetworkPage{Revision: strconv.FormatUint(s.Rev(), 10), Timestamp: s.Time().UTC().Format(time.RFC3339Nano), Category: q.Category, Total: len(all), Offset: q.Offset, Limit: q.Limit, Items: []NetworkObject{}}

	search := strings.ToLower(strings.TrimSpace(q.Search))
	for _, o := range all {
		if q.Identity != "" && !slices.Contains(o.RelatedIDs, q.Identity) && o.ID != q.Identity {
			continue
		}

		if search != "" && !strings.Contains(strings.ToLower(o.Label+" "+strings.Join(o.Addresses, " ")+" "+strings.Join(o.Tags, " ")), search) {
			continue
		}

		if p.Matched >= q.Offset && len(p.Items) < q.Limit {
			p.Items = append(p.Items, o)
		}

		p.Matched++
	}

	if q.Offset+len(p.Items) < p.Matched {
		p.NextOffset = new(q.Offset + len(p.Items))
	}

	return p
}

func (s *Snapshot) DebugNetworkTopology(id string, queries ...NetworkQuery) NetworkTopology {
	if id == "" {
		q := NetworkQuery{}
		if len(queries) > 0 {
			q = queries[0]
		}

		return s.debugNetworkOverview(q)
	}

	return s.debugNetworkFocusedTopology(id)
}

func (s *Snapshot) debugNetworkFocusedTopology(id string) NetworkTopology {
	t := NetworkTopology{Revision: strconv.FormatUint(s.Rev(), 10), Timestamp: s.Time().UTC().Format(time.RFC3339Nano), Objects: []NetworkObject{}, Relationships: []NetworkRelationship{}, ObjectLimit: 200, EdgeLimit: 1000}

	all := []NetworkObject{}
	for _, c := range []string{"users", "tags", "nodes"} {
		all = append(all, s.networkObjects(c)...)
	}

	nodeIDs := []string{}

	for _, o := range all {
		if o.Kind == "node" && (o.ID == id || slices.Contains(o.RelatedIDs, id)) {
			nodeIDs = append(nodeIDs, o.ID)
		}
	}

	if len(nodeIDs) == 0 && (strings.HasPrefix(id, "route:") || strings.HasPrefix(id, "service:")) {
		parts := strings.SplitN(id, ":", 3)
		if len(parts) > 1 {
			nodeIDs = append(nodeIDs, "node:"+parts[1])
		}
	}

	if len(nodeIDs) > 0 {
		for _, c := range []string{"routes", "services"} {
			all = append(all, s.networkObjects(c, nodeIDs...)...)
		}
	}

	slices.SortStableFunc(all, func(a, b NetworkObject) int {
		if a.ID == id {
			return -1
		}

		if b.ID == id {
			return 1
		}

		return 0
	})

	selected := map[string]bool{id: true}
	for _, o := range all {
		if o.ID == id {
			for _, r := range o.RelatedIDs {
				selected[r] = true
			}
		}

		if slices.Contains(o.RelatedIDs, id) {
			selected[o.ID] = true
		}
	}

	for _, o := range all {
		if !selected[o.ID] {
			continue
		}

		if len(t.Objects) == 200 {
			t.Omitted++
			continue
		}

		t.Objects = append(t.Objects, o)
	}

	present := map[string]bool{}
	for _, o := range t.Objects {
		present[o.ID] = true
	}

	for _, o := range t.Objects {
		for _, r := range o.RelatedIDs {
			if present[r] && len(t.Relationships) < 1000 {
				kind := "related to"
				if o.Kind == "tag" {
					kind = "tag ownership permission"
				}

				if o.Kind == "node" {
					kind = "owned by"
					if strings.HasPrefix(r, "tag:") {
						kind = "tag identity"
					}
				}

				t.Relationships = append(t.Relationships, NetworkRelationship{o.ID, r, kind})
			}
		}
	}

	return t
}

// debugNetworkOverview describes structural relationships; packet access is queried per node.
func (s *Snapshot) debugNetworkOverview(q NetworkQuery) NetworkTopology {
	t := NetworkTopology{Revision: strconv.FormatUint(s.Rev(), 10), Timestamp: s.Time().UTC().Format(time.RFC3339Nano), Objects: []NetworkObject{}, Relationships: []NetworkRelationship{}, ObjectLimit: 200, EdgeLimit: 1000}
	all := []NetworkObject{}
	byID := map[string]NetworkObject{}

	for _, category := range []string{"users", "tags", "nodes", "routes", "services"} {
		for _, o := range s.networkObjects(category) {
			if _, exists := byID[o.ID]; !exists {
				all = append(all, o)
				byID[o.ID] = o
			}
		}
	}
	// Retain ownership context even if a deleted user's record is absent.
	for _, o := range all {
		if o.Kind == "node" && o.OwnerID != "" {
			if _, exists := byID[o.OwnerID]; !exists {
				owner := networkObject(o.OwnerID, "user", o.OwnerID)
				byID[owner.ID] = owner
				all = append(all, owner)
			}
		}
	}

	counts := map[string]int{}

	for _, o := range all {
		if o.Kind == "node" {
			for _, id := range o.RelatedIDs {
				counts[id]++
			}
		}
	}

	for i := range all {
		if all[i].Kind == "user" || all[i].Kind == "tag" {
			all[i].MemberCount = counts[all[i].ID]
		}
	}

	rank := func(o NetworkObject) int {
		switch o.Kind {
		case "user", "tag":
			return 0
		case "node":
			return 1
		default:
			return 2
		}
	}

	slices.SortFunc(all, func(a, b NetworkObject) int {
		if rank(a) != rank(b) {
			return rank(a) - rank(b)
		}

		return strings.Compare(a.ID, b.ID)
	})

	eligible := networkOverviewSelection(all, byID, q)

	present := map[string]bool{}

	for _, o := range all {
		if !eligible[o.ID] {
			continue
		}

		connected := true

		if o.Kind == "node" || o.Kind == "route" || o.Kind == "service" {
			for _, id := range o.RelatedIDs {
				if !present[id] {
					connected = false
					break
				}
			}
		}

		if len(t.Objects) == t.ObjectLimit || !connected {
			t.Omitted++
			continue
		}

		t.Objects = append(t.Objects, o)
		present[o.ID] = true
	}

	t.Relationships = networkOverviewRelationships(t.Objects, present, t.EdgeLimit)

	return t
}

func networkOverviewSelection(all []NetworkObject, byID map[string]NetworkObject, q NetworkQuery) map[string]bool {
	eligible := map[string]bool{}
	search := strings.ToLower(strings.TrimSpace(q.Search))

	for _, o := range all {
		node := o
		if o.NodeID != "" && o.Kind != "node" {
			node = byID["node:"+o.NodeID]
		}

		if q.Identity != "" && o.ID != q.Identity && !slices.Contains(node.RelatedIDs, q.Identity) {
			continue
		}

		if search != "" && !strings.Contains(strings.ToLower(o.ID+" "+o.Label+" "+strings.Join(o.Addresses, " ")+" "+strings.Join(o.Tags, " ")), search) {
			continue
		}

		eligible[o.ID] = true
		if node.Kind == "node" {
			eligible[node.ID] = true
			for _, id := range node.RelatedIDs {
				eligible[id] = true
			}
		}
	}

	return eligible
}

func networkOverviewRelationships(objects []NetworkObject, present map[string]bool, limit int) []NetworkRelationship {
	relationships := []NetworkRelationship{}

	for _, o := range objects {
		for _, id := range o.RelatedIDs {
			if !present[id] || len(relationships) == limit {
				continue
			}

			kind := "related to"

			switch o.Kind {
			case "node":
				kind = "owned by"
				if strings.HasPrefix(id, "tag:") {
					kind = "tag identity"
				}
			case "tag":
				kind = "tag ownership permission"
			case "route":
				kind = "routed by"
			case "service":
				kind = "service on"
			}

			relationships = append(relationships, NetworkRelationship{o.ID, id, kind})
		}
	}

	return relationships
}

type networkPolicy interface {
	ExplainAccess(query policyv2.AccessQuery, raw []byte) policyv2.AccessExplanation
	SummarizeAccess(source, destination types.NodeView) ([]policyv2.AccessRange, error)
}
type NetworkAccessItem struct {
	Node         NetworkObject          `json:"node"`
	Ranges       []policyv2.AccessRange `json:"ranges"`
	Capabilities []string               `json:"capabilities"`
	Visible      bool                   `json:"visible"`
	Error        string                 `json:"error"`
}
type NetworkAccessPage struct {
	Revision   string              `json:"revision"`
	Timestamp  string              `json:"timestamp"`
	Direction  string              `json:"direction"`
	Total      int                 `json:"total"`
	Matched    int                 `json:"matched"`
	Offset     int                 `json:"offset"`
	Limit      int                 `json:"limit"`
	NextOffset *int                `json:"nextOffset"`
	Items      []NetworkAccessItem `json:"items"`
}

func networkNodeID(id string) (types.NodeID, error) {
	n, err := strconv.ParseUint(strings.TrimPrefix(id, "node:"), 10, 64)
	return types.NodeID(n), err
}

func (s *Snapshot) DebugNetworkAccess(ctx context.Context, q NetworkQuery) (NetworkAccessPage, error) {
	id, err := networkNodeID(q.ID)
	if err != nil {
		return NetworkAccessPage{}, err
	}

	selected, ok := s.GetNode(id)
	if !ok {
		return NetworkAccessPage{}, errNetworkNodeMissing
	}

	pm, ok := s.Policy().(networkPolicy)
	if !ok {
		return NetworkAccessPage{}, errNetworkPolicyUnavailable
	}

	q.Category = "nodes"

	p := s.DebugNetworkInventory(q)
	if q.OnlyPermitted {
		return s.debugNetworkPermittedAccess(ctx, q, p)
	}

	out := NetworkAccessPage{Revision: p.Revision, Timestamp: p.Timestamp, Direction: q.Direction, Total: p.Total, Matched: p.Matched, Offset: p.Offset, Limit: p.Limit, NextOffset: p.NextOffset, Items: []NetworkAccessItem{}}
	for _, o := range p.Items {
		err = ctx.Err()
		if err != nil {
			return out, err
		}

		item := s.networkAccessItem(pm, selected, o, q)

		out.Items = append(out.Items, item)
	}

	return out, nil
}

func (s *Snapshot) networkAccessItem(pm networkPolicy, selected types.NodeView, o NetworkObject, q NetworkQuery) NetworkAccessItem {
	otherID, _ := networkNodeID(o.ID)
	other, _ := s.GetNode(otherID)

	src, dst := selected, other
	if q.Direction == "incoming" {
		src, dst = other, selected
	}

	ranges, err := pm.SummarizeAccess(src, dst)
	if q.Protocol != nil || q.Port != nil {
		ranges = slices.DeleteFunc(ranges, func(r policyv2.AccessRange) bool {
			if len(r.Capabilities) > 0 {
				return false
			}

			if q.Protocol != nil && len(r.Protocols) > 0 && !slices.Contains(r.Protocols, *q.Protocol) {
				return true
			}

			return q.Port != nil && (*q.Port < r.First || *q.Port > r.Last)
		})
	}

	item := NetworkAccessItem{Node: o, Ranges: ranges, Capabilities: []string{}}
	if !q.OnlyPermitted {
		item.Visible = slices.Contains(s.ListPeerIDs(src.ID()), dst.ID())
	}

	if item.Ranges == nil {
		item.Ranges = []policyv2.AccessRange{}
	}

	if s.PolicyErr() != nil {
		item.Ranges = []policyv2.AccessRange{}
		item.Error = s.PolicyErr().Error()
	}

	if err != nil {
		item.Error = err.Error()
	}

	for _, r := range ranges {
		item.Capabilities = append(item.Capabilities, r.Capabilities...)
	}

	return item
}

// Permission filtering precedes paging so blocked candidates cannot hide connections.
func (s *Snapshot) debugNetworkPermittedAccess(ctx context.Context, q NetworkQuery, inventory NetworkPage) (NetworkAccessPage, error) {
	out := NetworkAccessPage{Revision: inventory.Revision, Timestamp: inventory.Timestamp, Direction: q.Direction, Total: inventory.Matched, Offset: inventory.Offset, Limit: inventory.Limit, Items: []NetworkAccessItem{}}

	err := s.PolicyErr()
	if err != nil {
		return out, err
	}

	id, _ := networkNodeID(q.ID)
	selected, _ := s.GetNode(id)
	pm, _ := s.Policy().(networkPolicy)
	search := strings.ToLower(strings.TrimSpace(q.Search))

	for _, o := range s.networkObjects("nodes") {
		err := ctx.Err()
		if err != nil {
			return out, err
		}

		if o.ID == fmt.Sprintf("node:%d", id) {
			continue
		}

		if q.Identity != "" && !slices.Contains(o.RelatedIDs, q.Identity) && o.ID != q.Identity {
			continue
		}

		if search != "" && !strings.Contains(strings.ToLower(o.Label+" "+strings.Join(o.Addresses, " ")+" "+strings.Join(o.Tags, " ")), search) {
			continue
		}

		item := s.networkAccessItem(pm, selected, o, q)
		if item.Error != "" {
			return out, fmt.Errorf("%w: %s", errNetworkPolicyUnavailable, item.Error)
		}

		if len(item.Ranges) == 0 && len(item.Capabilities) == 0 {
			continue
		}

		if out.Matched >= out.Offset && len(out.Items) < out.Limit {
			otherID, _ := networkNodeID(o.ID)

			src, dst := id, otherID
			if q.Direction == "incoming" {
				src, dst = otherID, id
			}

			item.Visible = slices.Contains(s.ListPeerIDs(src), dst)
			out.Items = append(out.Items, item)
		}

		out.Matched++
	}

	if out.Offset+len(out.Items) < out.Matched {
		out.NextOffset = new(out.Offset + len(out.Items))
	}

	return out, nil
}

type NetworkExplainQuery struct {
	EvidenceOffset, EvidenceResult         int
	Source, Destination, SourceIP, SSHUser string
	Protocol                               uint8
	Port                                   uint16
}
type NetworkExplainResult struct {
	SourceIP         string                     `json:"sourceIP"`
	DestinationIP    string                     `json:"destinationIP"`
	RouterID         string                     `json:"routerId"`
	Visible          bool                       `json:"visible"`
	RouteEvidence    []NetworkObject            `json:"routeEvidence"`
	EvidenceSelected bool                       `json:"evidenceSelected"`
	Policy           policyv2.AccessExplanation `json:"policy"`
}
type NetworkExplanation struct {
	Revision    string                 `json:"revision"`
	Timestamp   string                 `json:"timestamp"`
	Source      NetworkObject          `json:"source"`
	Destination NetworkObject          `json:"destination"`
	Results     []NetworkExplainResult `json:"results"`
	Observation string                 `json:"observation"`
	Routing     string                 `json:"routing"`
}

func (s *Snapshot) DebugNetworkExplain(ctx context.Context, q NetworkExplainQuery) (NetworkExplanation, error) {
	out := NetworkExplanation{Revision: strconv.FormatUint(s.Rev(), 10), Timestamp: s.Time().UTC().Format(time.RFC3339Nano), Results: []NetworkExplainResult{}, Observation: "Live reachability and application listening state are unknown.", Routing: "Client route and exit-node selection are unknown."}

	sid, err := networkNodeID(q.Source)
	if err != nil {
		return out, err
	}

	src, ok := s.GetNode(sid)
	if !ok {
		return out, errNetworkSourceMissing
	}

	out.Source = networkNode(src, s.Time())

	pm, ok := s.Policy().(networkPolicy)
	if !ok {
		return out, errNetworkPolicyUnavailable
	}

	sources := src.IPs()

	if q.SourceIP != "" {
		a, err := netip.ParseAddr(q.SourceIP)
		if err != nil || !src.HasIP(a) {
			return out, errNetworkSourceIP
		}

		sources = []netip.Addr{a}
	}

	dests := []netip.Addr{}

	var target types.NodeView

	if strings.HasPrefix(q.Destination, "node:") {
		did, err := networkNodeID(q.Destination)
		if err != nil {
			return out, err
		}

		target, ok = s.GetNode(did)
		if !ok {
			return out, errNetworkDestinationMissing
		}

		out.Destination = networkNode(target, s.Time())
		dests = target.IPs()
	} else {
		a, err := netip.ParseAddr(q.Destination)
		if err != nil {
			return out, err
		}

		dests = append(dests, a)

		out.Destination = networkObject(a.String(), "address", a.String())
		for _, n := range s.ListNodes().All() {
			if n.HasIP(a) {
				target = n
				out.Destination = networkNode(n, s.Time())

				break
			}
		}
	}

	if q.SSHUser != "" && !target.Valid() {
		return out, errNetworkSSHDestination
	}

	routeInventory := []NetworkObject{}
	if !target.Valid() {
		routeInventory = s.networkObjects("routes")
	}

	compatible := false

	for _, dstIP := range dests {
		for _, srcIP := range sources {
			if srcIP.Is4() != dstIP.Is4() {
				continue
			}

			compatible = true

			err = ctx.Err()
			if err != nil {
				return out, err
			}

			candidates := s.networkRouteCandidates(target, dstIP)
			for _, dst := range candidates {
				r := NetworkExplainResult{SourceIP: srcIP.String(), DestinationIP: dstIP.String(), Visible: slices.Contains(s.ListPeerIDs(src.ID()), dst.ID()), RouteEvidence: []NetworkObject{}}
				if !target.Valid() {
					r.RouterID = fmt.Sprintf("node:%d", dst.ID())
					matchers, _ := s.Policy().MatchersForNode(src)

					visibleRoutes := s.RoutesForPeer(src, dst, matchers)
					for _, route := range routeInventory {
						if route.NodeID != fmt.Sprint(dst.ID()) {
							continue
						}

						p, _ := netip.ParsePrefix(route.Label)
						if p.Contains(dstIP) {
							route.SourceVisible = slices.Contains(visibleRoutes, p)
							r.RouteEvidence = append(r.RouteEvidence, route)
						}
					}
				}

				r.EvidenceSelected = len(out.Results) == q.EvidenceResult

				r.Policy = pm.ExplainAccess(policyv2.AccessQuery{Source: src, Destination: dst, SourceIP: srcIP, DestinationIP: dstIP, Protocol: q.Protocol, Port: q.Port, SSHUser: q.SSHUser, EvidenceOffset: q.EvidenceOffset, OmitEvidence: len(out.Results) != q.EvidenceResult}, s.PolicySource())
				if s.PolicyErr() != nil {
					r.Policy.Packet = "unavailable"
					r.Policy.Diagnostic = s.PolicyErr().Error()
				}

				out.Results = append(out.Results, r)
				if len(out.Results) >= 100 {
					out.Routing = "Candidate results limited to 100; client route selection remains unknown."
					return out, nil
				}
			}
		}
	}

	if len(out.Results) == 0 {
		reason := "No compatible source and destination address family is available."
		if compatible {
			reason = "No advertising router candidate covers this destination; policy permission is unavailable."
		}

		out.Routing = reason
		out.Results = append(out.Results, NetworkExplainResult{RouteEvidence: []NetworkObject{}, Policy: policyv2.AccessExplanation{Packet: "unavailable", SSH: "unavailable", Reason: reason, Rules: []policyv2.AccessRuleReference{}, Capabilities: []policyv2.AccessCapability{}}})
	}

	return out, nil
}

func (s *Snapshot) networkRouteCandidates(target types.NodeView, address netip.Addr) []types.NodeView {
	if target.Valid() {
		return []types.NodeView{target}
	}

	candidates := []types.NodeView{}

	for _, n := range s.ListNodes().All() {
		for _, p := range n.AnnouncedRoutes() {
			if p.Contains(address) {
				candidates = append(candidates, n)
				break
			}
		}
	}

	return candidates
}
