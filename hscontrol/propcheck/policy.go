package propcheck

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/netip"
	"slices"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/peercap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/wgengine/filter"
)

// DrawPolicy draws every field through Rapid, so failures shrink policy
// rules and history, rather than merely shrinking a seed for another generator.
//
//nolint:goconst // Repeated aliases keep the generated policy schema readable.
func DrawPolicy(t *rapid.T) []byte {
	aliases := []string{
		"*", "u1@", "u2@", "group:a", "tag:srv", "tag:router",
		"autogroup:member", "autogroup:tagged", "lan", "100.64.0.1", "fd7a:115c:a1e0::2",
	}
	pick := func(pool []string) []string {
		return rapid.SliceOfN(rapid.SampledFrom(pool), 1, 3).Draw(t, "aliases")
	}
	pol := map[string]any{
		"groups":        map[string][]string{"group:a": pick([]string{"u1@", "u2@", "u3@"})},
		"tagOwners":     map[string][]string{"tag:srv": {"u1@"}, "tag:router": {"u2@"}},
		"hosts":         map[string]string{"lan": rapid.SampledFrom([]string{"10.0.0.0/24", "2001:db8::/64"}).Draw(t, "host")},
		"autoApprovers": map[string]any{"routes": map[string][]string{"10.0.0.0/24": {"tag:router"}}},
	}
	grants, acls := []any{}, []any{}

	for range rapid.IntRange(0, 5).Draw(t, "rules") {
		src := pick(aliases)

		dst := pick(append(slices.Clone(aliases), "autogroup:self", "autogroup:internet"))
		if slices.Contains(dst, "autogroup:self") {
			src = pick([]string{"u1@", "u2@", "group:a", "autogroup:member"})
		}

		switch rapid.IntRange(0, 3).Draw(t, "rule kind") {
		case 0:
			// IPv6 literals need bracket syntax in ACL destinations; grants cover them.
			dst = pick([]string{"*", "u1@", "group:a", "tag:srv", "autogroup:self", "lan"})
			if slices.Contains(dst, "autogroup:self") {
				src = pick([]string{"u1@", "u2@", "group:a", "autogroup:member"})
			}

			for i := range dst {
				dst[i] += ":" + rapid.SampledFrom([]string{"*", "22", "80,443"}).Draw(t, "ports")
			}

			acls = append(acls, map[string]any{"action": "accept", "src": src, "dst": dst})
		case 1:
			grants = append(grants, map[string]any{
				"src": src, "dst": dst,
				"ip": pick([]string{"*", "tcp:443", "udp:53", "icmp:*"}),
			})
		case 2:
			for i := range dst {
				if dst[i] == "autogroup:internet" {
					dst[i] = "8.8.8.0/24"
				}
			}

			grants = append(grants, map[string]any{
				"src": src, "dst": dst,
				"app": map[string]any{"example.com/cap/test": []any{map[string]any{"role": rapid.SampledFrom([]string{"read", "write"}).Draw(t, "role")}}},
			})
		case 3:
			grants = append(grants, map[string]any{
				"src": src, "dst": []string{"lan"},
				"via": []string{"tag:router"}, "ip": []string{"tcp:443"},
			})
		}
	}

	pol["grants"], pol["acls"] = grants, acls
	if rapid.Bool().Draw(t, "default allow") && len(grants)+len(acls) == 0 {
		delete(pol, "grants")
		delete(pol, "acls")
	}

	ssh := make([]any, 0, 2)

	for range rapid.IntRange(0, 2).Draw(t, "ssh rules") {
		action := rapid.SampledFrom([]string{"accept", "check"}).Draw(t, "ssh action")

		dst := []string{"autogroup:self"}
		if action == "accept" {
			dst = pick([]string{"autogroup:self", "tag:srv", "tag:router"})
		}

		ssh = append(ssh, map[string]any{
			"action": action, "src": pick([]string{"u1@", "group:a", "autogroup:member"}),
			"dst": dst, "users": pick([]string{"root", "autogroup:nonroot"}),
		})
	}

	pol["ssh"] = ssh
	pol["nodeAttrs"] = []any{map[string]any{"target": pick(aliases), "attr": pick([]string{"foo", "bar", "randomize-client-port"})}}

	pol["randomizeClientPort"] = rapid.Bool().Draw(t, "randomize port")
	if dm := DrawDERPMap(t, true); dm != nil {
		pol["derpMap"] = dm
	}

	return policyJSON(t, pol)
}

// ReorderPolicy reverses rule order and optionally duplicates one rule.
// Duplicate app grants intentionally retain their multiplicity.
func ReorderPolicy(t require.TestingT, doc []byte, duplicate bool) []byte {
	var pol map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &pol))

	for _, key := range []string{"grants", "acls"} {
		var rules []json.RawMessage
		if b, ok := pol[key]; ok {
			require.NoError(t, json.Unmarshal(b, &rules))
			slices.Reverse(rules)

			if duplicate && len(rules) > 0 {
				rules = append(rules, rules[0])
			}

			pol[key] = policyJSON(t, rules)
		}
	}

	return policyJSON(t, pol)
}

func policyJSON(t require.TestingT, v any) []byte {
	b, err := json.Marshal(v)
	require.NoError(t, err)

	return b
}

// PacketSelector is one bounded input selector, not a policy parser. The zero
// value selects every node; at most one field is populated by the generator.
type PacketSelector struct {
	User string
	Tag  string
	IP   netip.Addr
}

func (s PacketSelector) alias() string {
	switch {
	case s.User != "":
		return s.User + "@"
	case s.Tag != "":
		return s.Tag
	case s.IP.IsValid():
		return s.IP.String()
	default:
		return "*"
	}
}

func (s PacketSelector) matches(m World, n *types.Node, ip netip.Addr) bool {
	switch {
	case s.User != "":
		if len(n.Tags) != 0 || n.UserID == nil {
			return false
		}

		for _, u := range m.Users {
			if u.ID == *n.UserID && u.Name == s.User {
				return true
			}
		}

		return false
	case s.Tag != "":
		return slices.Contains(n.Tags, s.Tag)
	case s.IP.IsValid():
		return s.IP == ip
	default:
		return true
	}
}

type PacketGrant struct {
	Src, Dst    PacketSelector
	Protocol    ipproto.Proto
	First, Last uint16
}

// PacketIntent is immutable after construction so document history can retain
// it across replacements, reordering and duplicate grants without aliasing.
// It specifies only new TCP/UDP flows between distinct nodes, not return traffic,
// subnet routing, SSH, app capabilities or general alias interpretation.
type PacketIntent struct {
	Grants []PacketGrant
}

func (p *PacketIntent) Document(t require.TestingT) []byte {
	return p.document(t, nil)
}

func (p *PacketIntent) document(t require.TestingT, app *AppIntent) []byte {
	grants := make([]any, 0, len(p.Grants))
	tags := map[string][]string{}

	for _, g := range p.Grants {
		for _, s := range []PacketSelector{g.Src, g.Dst} {
			if s.Tag != "" {
				tags[s.Tag] = []string{}
			}
		}

		proto := "tcp"
		if g.Protocol == ipproto.UDP {
			proto = "udp"
		}

		grants = append(grants, map[string]any{
			"src": []string{g.Src.alias()}, "dst": []string{g.Dst.alias()},
			"ip": []string{fmt.Sprintf("%s:%d-%d", proto, g.First, g.Last)},
		})
	}

	if app != nil {
		for _, g := range app.Grants {
			for _, s := range []PacketSelector{g.Src, g.Dst} {
				if s.Tag != "" {
					tags[s.Tag] = []string{}
				}
			}

			grants = append(grants, map[string]any{
				"src": []string{g.Src.alias()}, "dst": []string{g.Dst.alias()}, "app": g.Caps,
			})
		}
	}

	return policyJSON(t, map[string]any{"grants": grants, "tagOwners": tags})
}

const packetMaxPortWidth = 3

var packetPortStarts = []uint16{0, 1, 22, 53, 443, 65534, 65535}

// DrawPacketIntent includes a live literal-IP witness, then up to three broader
// grants. Fixed port islands leave denied neighbors even when selectors are *.
func DrawPacketIntent(t *rapid.T, m World) *PacketIntent {
	ids := slices.Sorted(maps.Keys(m.Nodes))

	selectors := []PacketSelector{{}, {Tag: "tag:srv"}, {Tag: "tag:router"}}
	for _, u := range m.Users {
		selectors = append(selectors, PacketSelector{User: u.Name})
	}

	var witnesses []PacketGrant

	for _, id := range ids {
		n := m.Nodes[id]
		for _, tag := range n.Tags {
			selectors = append(selectors, PacketSelector{Tag: tag})
		}

		for _, ip := range []*netip.Addr{n.IPv4, n.IPv6} {
			if ip == nil {
				continue
			}

			selectors = append(selectors, PacketSelector{IP: *ip})

			for _, other := range ids {
				if other == id {
					continue
				}

				for _, dst := range []*netip.Addr{m.Nodes[other].IPv4, m.Nodes[other].IPv6} {
					if dst != nil && ip.Is4() == dst.Is4() {
						witnesses = append(witnesses, PacketGrant{Src: PacketSelector{IP: *ip}, Dst: PacketSelector{IP: *dst}})
					}
				}
			}
		}
	}

	require.NotEmpty(t, witnesses, "packet intent needs two nodes sharing an address family")

	p := &PacketIntent{Grants: []PacketGrant{rapid.SampledFrom(witnesses).Draw(t, "allowed witness")}}
	for range rapid.IntRange(0, 3).Draw(t, "extra packet grants") {
		p.Grants = append(p.Grants, PacketGrant{
			Src: rapid.SampledFrom(selectors).Draw(t, "packet source"),
			Dst: rapid.SampledFrom(selectors).Draw(t, "packet destination"),
		})
	}

	for i := range p.Grants {
		g := &p.Grants[i]
		g.Protocol = rapid.SampledFrom([]ipproto.Proto{ipproto.TCP, ipproto.UDP}).Draw(t, "packet protocol")
		g.First = rapid.SampledFrom(packetPortStarts).Draw(t, "first port")
		g.Last = g.First + rapid.Uint16Range(0, min(packetMaxPortWidth, 65535-g.First)).Draw(t, "port width")
	}

	return p
}

// Allows derives expected permission solely from generated inputs. No compiler,
// matcher, fresh renderer or emitted filter participates in this decision.
func (p *PacketIntent) Allows(m World, src, dst types.NodeID, srcIP, dstIP netip.Addr, port uint16, proto ipproto.Proto) bool {
	for _, g := range p.Grants {
		if g.Protocol == proto && g.First <= port && port <= g.Last &&
			g.Src.matches(m, m.Nodes[src], srcIP) && g.Dst.matches(m, m.Nodes[dst], dstIP) {
			return true
		}
	}

	return false
}

// CheckPacketIntent evaluates the consumer's actual rules using the pinned
// Tailscale filter (new TCP SYN or UDP, no shared conntrack). It returns the union
// of peers with incoming or outgoing allowed witnesses. This is necessary
// visibility, not exact membership: same-user peers may have no allowed flow.
// Probes cover every generated range and its neighbors even after revocation;
// wider manual ranges retain bounded probes only while present in the intent.
func CheckPacketIntent(t require.TestingT, m World, intent *PacketIntent, destination types.NodeID, rules []tailcfg.FilterRule) []types.NodeID {
	dst := m.Nodes[destination]
	require.NotNil(t, dst)

	var local netipx.IPSetBuilder

	for _, ip := range []*netip.Addr{dst.IPv4, dst.IPv6} {
		if ip != nil {
			local.Add(*ip)
		}
	}

	localNets, err := local.IPSet()
	require.NoError(t, err)
	matches, err := filter.MatchesFromFilterRules(rules)
	require.NoError(t, err)

	actual := filter.New(matches, nil, localNets, nil, nil, logger.Discard)

	ports := []uint16{0, 32768, 65535}

	for _, first := range packetPortStarts {
		if first > 0 {
			ports = append(ports, first-1)
		}

		for port := uint32(first); port <= min(uint32(first)+packetMaxPortWidth+1, 65535); port++ {
			ports = append(ports, uint16(port)) //nolint:gosec // Bounded by 65535.
		}
	}

	for _, g := range intent.Grants {
		// Generated ranges have at most four ports; larger manual ranges
		// stay bounded with the first four ports, midpoint and endpoint.
		ports = append(ports, g.Last, g.First+(g.Last-g.First)/2)
		for port := uint32(g.First); port <= uint32(g.Last) && port < uint32(g.First)+4; port++ {
			ports = append(ports, uint16(port)) //nolint:gosec // Bounded by the uint16 Last field.
		}

		if g.First > 0 {
			ports = append(ports, g.First-1)
		}

		if g.Last < 65535 {
			ports = append(ports, g.Last+1)
		}
	}

	slices.Sort(ports)
	ports = slices.Compact(ports)

	var peers []types.NodeID

	for _, id := range slices.Sorted(maps.Keys(m.Nodes)) {
		if id == destination {
			continue
		}

		src := m.Nodes[id]
		allowed := false

		for family, srcIP := range []*netip.Addr{src.IPv4, src.IPv6} {
			dstIP := []*netip.Addr{dst.IPv4, dst.IPv6}[family]
			if srcIP == nil || dstIP == nil {
				continue
			}

			for _, proto := range []ipproto.Proto{ipproto.TCP, ipproto.UDP} {
				for _, port := range ports {
					want := intent.Allows(m, id, destination, *srcIP, *dstIP, port, proto)
					got := actual.Check(*srcIP, *dstIP, port, proto) == filter.Accept
					require.Equal(t, want, got, "packet %d (%s) to %d (%s):%d proto %s", id, srcIP, destination, dstIP, port, proto)
					allowed = allowed || want || intent.Allows(m, destination, id, *dstIP, *srcIP, port, proto)
				}
			}
		}

		if allowed {
			peers = append(peers, id)
		}
	}

	return peers
}

// AppGrant carries custom peer capabilities, never Node.CapMap or network ports.
// Caps and its ordered values are owned inputs, immutable after construction.
type AppGrant struct {
	Src, Dst PacketSelector
	Caps     tailcfg.PeerCapMap
}

// AppIntent specifies ordered node-to-node custom capability grants only.
// It excludes companion grants, via, public/subnet destinations and nodeAttrs.
type AppIntent struct {
	Grants []AppGrant
}

// Document composes independent packet and app inputs in one policy document.
// An explicit empty packet intent proves app-only grants open no TCP/UDP ports.
func (a *AppIntent) Document(t require.TestingT, packet *PacketIntent) []byte {
	return packet.document(t, a)
}

// Reordered preserves old history while changing the actual ordered input.
// Payload maps can be shared because neither model nor serializer mutates them.
func (a *AppIntent) Reordered(duplicate bool) *AppIntent {
	next := &AppIntent{Grants: slices.Clone(a.Grants)}
	slices.Reverse(next.Grants)

	if duplicate && len(next.Grants) > 0 {
		next.Grants = append(next.Grants, next.Grants[0])
	}

	return next
}

// DrawAppIntent includes a live literal witness and broader identity selectors.
func DrawAppIntent(t *rapid.T, m World) *AppIntent {
	ids := slices.Sorted(maps.Keys(m.Nodes))

	selectors := []PacketSelector{{}, {Tag: "tag:srv"}, {Tag: "tag:router"}}
	for _, u := range m.Users {
		selectors = append(selectors, PacketSelector{User: u.Name})
	}

	var witnesses []AppGrant

	for _, id := range ids {
		n := m.Nodes[id]
		for _, tag := range n.Tags {
			selectors = append(selectors, PacketSelector{Tag: tag})
		}

		for family, ip := range []*netip.Addr{n.IPv4, n.IPv6} {
			if ip == nil {
				continue
			}

			selectors = append(selectors, PacketSelector{IP: *ip})

			for _, other := range ids {
				dst := []*netip.Addr{m.Nodes[other].IPv4, m.Nodes[other].IPv6}[family]
				if id != other && dst != nil {
					witnesses = append(witnesses, AppGrant{Src: PacketSelector{IP: *ip}, Dst: PacketSelector{IP: *dst}})
				}
			}
		}
	}

	require.NotEmpty(t, witnesses, "app intent needs two nodes sharing an address family")

	a := &AppIntent{Grants: []AppGrant{rapid.SampledFrom(witnesses).Draw(t, "app witness")}}
	for range rapid.IntRange(0, 3).Draw(t, "extra app grants") {
		a.Grants = append(a.Grants, AppGrant{
			Src: rapid.SampledFrom(selectors).Draw(t, "app source"),
			Dst: rapid.SampledFrom(selectors).Draw(t, "app destination"),
		})
	}

	for i := range a.Grants {
		caps := tailcfg.PeerCapMap{}

		for _, key := range rapid.SliceOfNDistinct(rapid.SampledFrom([]peercap.Cap{
			"example.com/cap/read", "example.com/cap/write", "example.com/cap/audit",
		}), 1, 3, func(key peercap.Cap) peercap.Cap { return key }).Draw(t, "app keys") {
			var values []tailcfg.RawMessage

			if rapid.Bool().Draw(t, "app nonnil values") {
				values = make([]tailcfg.RawMessage, 0, 3)
				for range rapid.IntRange(0, 3).Draw(t, "app values") {
					values = append(values, tailcfg.RawMessage(policyJSON(t, map[string]any{
						"role":  rapid.SampledFrom([]string{"read", "write", "audit"}).Draw(t, "app role"),
						"level": rapid.IntRange(0, 2).Draw(t, "app level"),
					})))
				}
			}

			caps[key] = values
		}

		a.Grants[i].Caps = caps
	}

	return a
}

// Capabilities scans only owned input grants and World identities. Missing keys
// differ from present keys with no values; repeated values remain repeated.
func (a *AppIntent) Capabilities(m World, src, dst types.NodeID, srcIP, dstIP netip.Addr) tailcfg.PeerCapMap {
	want := tailcfg.PeerCapMap{}

	for _, g := range a.Grants {
		if g.Src.matches(m, m.Nodes[src], srcIP) && g.Dst.matches(m, m.Nodes[dst], dstIP) {
			for key, values := range g.Caps {
				want[key] = append(want[key], values...)
			}
		}
	}

	return want
}

// CheckAppIntent observes the pinned consumer, including unexpected keys after
// revocation. Only destinations require matching sources as peers; app-only
// grants do not imply symmetric visibility or permission to open network ports.
func CheckAppIntent(t require.TestingT, m World, intent *AppIntent, destination types.NodeID, rules []tailcfg.FilterRule) []types.NodeID {
	dst := m.Nodes[destination]
	require.NotNil(t, dst)

	matches, err := filter.MatchesFromFilterRules(rules)
	require.NoError(t, err)

	actual := filter.New(matches, nil, nil, nil, nil, logger.Discard)

	var peers []types.NodeID

	for _, id := range slices.Sorted(maps.Keys(m.Nodes)) {
		if id == destination {
			continue
		}

		src := m.Nodes[id]
		visible := false

		for family, srcIP := range []*netip.Addr{src.IPv4, src.IPv6} {
			dstIP := []*netip.Addr{dst.IPv4, dst.IPv6}[family]
			if srcIP == nil || dstIP == nil {
				continue
			}

			want := intent.Capabilities(m, id, destination, *srcIP, *dstIP)
			got := actual.CapsWithValues(*srcIP, *dstIP)
			require.Len(t, got, len(want), "app keys %d (%s) to %d (%s): want=%v got=%v", id, srcIP, destination, dstIP, want, got)

			for _, key := range slices.Sorted(maps.Keys(want)) {
				values, present := got[key]
				require.True(t, present, "missing app key %q from %d to %d", key, id, destination)
				require.True(t, slices.Equal(want[key], values), "app values %q from %d (%s) to %d (%s): want=%v got=%v", key, id, srcIP, destination, dstIP, want[key], values)
			}

			visible = visible || len(want) > 0
		}

		if visible {
			peers = append(peers, id)
		}
	}

	return peers
}

// SSHGrant selects whole user/tag identities, never literal addresses. Self
// means the source's user-owned devices; tagged creators confer no ownership.
type SSHGrant struct {
	Src    PacketSelector
	DstTag string
	Self   bool
	Check  bool
	Users  []string
}

// SSHIntent and its login slices are immutable after construction. The domain
// excludes nonroot/localpart, OS accounts, authentication and network access.
type SSHIntent struct {
	Grants []SSHGrant
}

// AppendDocument adds SSH to an existing packet/app document without replacing
// its grants, tag owners or DERP overlay. Callers carry explicit packet intent.
func (s *SSHIntent) AppendDocument(t require.TestingT, doc []byte) []byte {
	var pol map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &pol))

	tags := map[string][]string{}
	if b, ok := pol["tagOwners"]; ok {
		require.NoError(t, json.Unmarshal(b, &tags))
	}

	rules := make([]any, 0, len(s.Grants))
	for _, g := range s.Grants {
		require.False(t, g.Src.IP.IsValid(), "SSH literal selectors are outside the intent domain")
		require.NotEqual(t, g.Src.User == "", g.Src.Tag == "", "SSH source must be one user or tag")
		require.NotEqual(t, g.Self, g.DstTag != "", "SSH destination must be self or tag")
		require.False(t, g.Src.Tag != "" && (g.Check || g.Self), "check/self sources must be users")

		for _, login := range g.Users {
			require.Contains(t, []string{"root", "alice", "bob"}, login)
		}

		for _, tag := range []string{g.Src.Tag, g.DstTag} {
			if tag != "" {
				if _, exists := tags[tag]; !exists {
					tags[tag] = []string{}
				}
			}
		}

		dst, action := g.DstTag, "accept"
		if g.Self {
			dst = "autogroup:self"
		}

		if g.Check {
			action = "check"
		}

		rules = append(rules, map[string]any{"src": []string{g.Src.alias()}, "dst": []string{dst}, "users": g.Users, "action": action})
	}

	pol["ssh"], pol["tagOwners"] = policyJSON(t, rules), policyJSON(t, tags)

	return policyJSON(t, pol)
}

func (s *SSHIntent) Reordered(duplicate bool) *SSHIntent {
	next := &SSHIntent{Grants: slices.Clone(s.Grants)}
	slices.Reverse(next.Grants)

	if duplicate && len(next.Grants) > 0 {
		next.Grants = append(next.Grants, next.Grants[0])
	}

	return next
}

func DrawSSHIntent(t *rapid.T, m World) *SSHIntent {
	sources := make([]PacketSelector, 0, 2+len(m.Users))

	sources = append(sources, PacketSelector{Tag: "tag:srv"}, PacketSelector{Tag: "tag:router"})
	for _, u := range m.Users {
		sources = append(sources, PacketSelector{User: u.Name})
	}

	s := &SSHIntent{}
	for range rapid.IntRange(1, 4).Draw(t, "ssh grants") {
		g := SSHGrant{
			Src:    rapid.SampledFrom(sources).Draw(t, "ssh source"),
			DstTag: rapid.SampledFrom([]string{"tag:srv", "tag:router"}).Draw(t, "ssh destination"),
			Users:  rapid.SliceOfNDistinct(rapid.SampledFrom([]string{"root", "alice", "bob"}), 1, 3, func(s string) string { return s }).Draw(t, "ssh logins"),
		}
		if g.Src.User != "" {
			g.Check = rapid.Bool().Draw(t, "ssh check")

			g.Self = rapid.Bool().Draw(t, "ssh self")
			if g.Self {
				g.DstTag = ""
			}
		}

		s.Grants = append(s.Grants, g)
	}

	return s
}

// Decision depends only on input identities and grants. Check dominates accept
// regardless of document order; this does not predict callback authorization.
func (s *SSHIntent) Decision(m World, source, destination types.NodeID, login string) string {
	src, dst := m.Nodes[source], m.Nodes[destination]
	decision := "deny"

	for _, g := range s.Grants {
		if !slices.Contains(g.Users, login) || !g.Src.matches(m, src, netip.Addr{}) {
			continue
		}

		matches := slices.Contains(dst.Tags, g.DstTag)
		if g.Self {
			matches = len(src.Tags) == 0 && len(dst.Tags) == 0 && src.UserID != nil && dst.UserID != nil && *src.UserID == *dst.UserID
		}

		if matches {
			if g.Check {
				return "check"
			}

			decision = "accept"
		}
	}

	return decision
}

// CheckSSHIntent interprets only the pinned tailcfg SSH protocol's bounded
// emitted shape. The actual tailssh evaluator is unexported; this is not an SSH
// login test. Strict whole-struct checks reject unsupported fields rather than
// silently overlooking a principal, expiration, mapping or action restriction.
func CheckSSHIntent(t require.TestingT, m World, intent *SSHIntent, destination types.NodeID, policy *tailcfg.SSHPolicy, serverURL string) {
	require.NotNil(t, policy, "SSH policy must explicitly clear revoked rules")
	require.NotNil(t, m.Nodes[destination])

	sources := map[netip.Addr]types.NodeID{
		netip.MustParseAddr("192.0.2.254"): 0, netip.MustParseAddr("2001:db8::ffff"): 0,
	}

	for id, n := range m.Nodes {
		for _, ip := range []*netip.Addr{n.IPv4, n.IPv6} {
			if ip != nil {
				sources[*ip] = id
			}
		}
	}

	for _, rule := range policy.Rules {
		require.NotNil(t, rule, "unsupported SSH rule")
		require.Equal(t, &tailcfg.SSHRule{Principals: rule.Principals, SSHUsers: rule.SSHUsers, Action: rule.Action}, rule, "unsupported SSH rule fields")

		for _, principal := range rule.Principals {
			require.NotNil(t, principal, "unsupported SSH principal")
			require.Equal(t, &tailcfg.SSHPrincipal{NodeIP: principal.NodeIP}, principal, "unsupported SSH principal fields")
			ip, err := netip.ParseAddr(principal.NodeIP)
			require.NoError(t, err, "SSH principal must be one address")

			if _, live := sources[ip]; !live {
				sources[ip] = 0 // Also probe stale or invented emitted addresses.
			}
		}

		for login, local := range rule.SSHUsers {
			require.Contains(t, []string{"root", "alice", "bob", "charlie", "0"}, login, "unsupported SSH login")
			require.True(t, local == "" || (login != "0" && local == login), "unsupported SSH mapping")
		}

		require.NotNil(t, rule.Action, "unsupported SSH action")

		wantAction := tailcfg.SSHAction{}

		switch {
		case rule.Action.Reject:
			wantAction.Reject = true
		case rule.Action.Accept:
			wantAction = tailcfg.SSHAction{Accept: true, AllowAgentForwarding: true, AllowLocalPortForwarding: true, AllowRemotePortForwarding: true}
		default:
			wantAction.HoldAndDelegate = serverURL + "/machine/ssh/action/$SRC_NODE_ID/to/$DST_NODE_ID?local_user=$LOCAL_USER"
		}

		require.Equal(t, &wantAction, rule.Action, "unsupported SSH action fields")
	}

	for _, ip := range slices.SortedFunc(maps.Keys(sources), netip.Addr.Compare) {
		for _, login := range []string{"root", "alice", "bob", "charlie", "0"} {
			want := "deny"
			if id := sources[ip]; id != 0 {
				want = intent.Decision(m, id, destination, login)
			}

			require.Equal(t, want, sshDecision(policy, ip, login), "SSH decision source=%s destination=%d login=%s", ip, destination, login)
		}
	}
}

// Pinned tailssh matchRuleWithUserLookup processes the first matching rule;
// Reject bypasses SSHUsers. Wildcard and '=' are rejected above because they
// require account lookup outside this domain. An empty exact mapping denies.
func sshDecision(policy *tailcfg.SSHPolicy, source netip.Addr, login string) string {
	for _, rule := range policy.Rules {
		matches := slices.ContainsFunc(rule.Principals, func(p *tailcfg.SSHPrincipal) bool {
			ip, _ := netip.ParseAddr(p.NodeIP)
			return ip == source
		})
		if !matches {
			continue
		}

		if rule.Action.Reject {
			return "deny"
		}

		if rule.SSHUsers[login] == "" {
			continue
		}

		if rule.Action.Accept {
			return "accept"
		}

		return "check"
	}

	return "deny"
}
