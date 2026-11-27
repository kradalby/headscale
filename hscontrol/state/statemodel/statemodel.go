// Package statemodel holds what headscale's State stores, and what its
// clients are served, to policymodel's model: the judges that read
// production types, which every level of the system below the policy
// shares. policymodel imports none of it, which keeps it an oracle.
package statemodel

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/capver"
	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
)

// Joined is how a node registered, as a level registered it: what a
// login or a restart needs, and what production must hold of it.
type Joined struct {
	Method string
	// Key is the pre-auth key it registered with, "" when it has none to
	// log in again with; KeyUser the key's user, or the user who made a
	// tagged key, 0 for a tags-only key.
	Key       string
	KeyUser   uint
	Ephemeral bool
	// Tagged is set for a tagged key, which outlives the user who made
	// it; a user's own key goes with the user.
	Tagged bool
}

// Stored holds what l's State stored to the model l was driven to: every
// node equals the model's on what the model holds and on how it joined,
// the users equal the model's, and every database row equals its node in
// memory. It says how they differ, or "".
func Stored(l Level) string {
	s, w := l.State(), l.Model()
	snap := s.Snapshot()
	users, nodes := w.Topology.Build()

	held, want := make([]types.NodeID, 0, len(nodes)), make([]types.NodeID, 0, len(nodes))

	for _, nv := range snap.ListNodes().All() {
		held = append(held, nv.ID())
	}

	for _, tn := range nodes {
		want = append(want, tn.ID)
	}

	if !slices.Equal(held, want) {
		return fmt.Sprintf("stored: the State holds nodes %v, the model %v", held, want)
	}

	for i, tn := range nodes {
		nv, _ := snap.GetNode(tn.ID)

		if d := storedDiff(nv.AsStruct(), tn, w.Topology.Nodes[i], l.Joined(tn.ID)); d != "" {
			return fmt.Sprintf("stored: n%d: %s", tn.ID, d)
		}
	}

	stored, err := s.ListAllUsers()
	if err != nil {
		return fmt.Sprintf("stored: users: %v", err)
	}

	if h, m := usersOf(stored), usersOf(users); h != m {
		return fmt.Sprintf("stored: the State holds users\n%s\nthe model\n%s", h, m)
	}

	rows, err := s.DB().ListNodes()
	if err != nil {
		return fmt.Sprintf("persisted: %v", err)
	}

	ids := make([]types.NodeID, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
	}

	if !slices.Equal(ids, want) {
		return fmt.Sprintf("persisted: the database holds nodes %v, the model %v", ids, want)
	}

	for _, row := range rows {
		nv, _ := snap.GetNode(row.ID)

		if d := rowDiff(row, nv.AsStruct()); d != "" {
			return fmt.Sprintf("persisted: n%d's row differs from the node in memory: %s", row.ID, d)
		}
	}

	return ""
}

// usersOf is users as the policy reads them, in ID order.
func usersOf(users []types.User) string {
	users = slices.Clone(users)
	slices.SortFunc(users, func(a, b types.User) int { return int(a.ID) - int(b.ID) }) //nolint:gosec // small

	var sb strings.Builder

	for _, u := range users {
		fmt.Fprintf(&sb, "u%d %q <%s> %s\n", u.ID, u.Name, u.Email, u.ProviderIdentifier.String)
	}

	return sb.String()
}

// NodeDiff is how got, as production holds it, differs from model node n
// of w, and from how it joined, or "".
func NodeDiff(got *types.Node, w policymodel.World, n policymodel.Node, j Joined) string {
	return storedDiff(got, w.Topology.BuildNode(n), n, j)
}

// Served holds the wire entries a client holds — its own first, then its
// peers' — to what the State stores and the config fixed: the fields no
// model judge reads (a stable ID, a name, endpoints, a home DERP, a last
// seen, a creation time, the baseline capabilities an own entry carries,
// what a peer's hostinfo says of it, the version a peer's entry is
// rendered for and the capabilities it carries), which a render drops or
// invents for held and fresh sessions alike, so only the store can say.
// cv is the capability version the client speaks. It says how they
// differ, or "".
func Served(l Level, cfg *types.Config, cv tailcfg.CapabilityVersion, self tailcfg.NodeView, peers []tailcfg.NodeView) string {
	snap := l.State().Snapshot()

	for i, e := range append([]tailcfg.NodeView{self}, peers...) {
		if !e.Valid() {
			continue
		}

		id := types.NodeID(e.ID()) //nolint:gosec // small

		nv, ok := snap.GetNode(id)
		if !ok {
			// A peer the client has not learned is gone yet.
			continue
		}

		if d := servedDiff(cfg, snap.DNS(), cv, e, nv, i == 0); d != "" {
			return fmt.Sprintf("served: n%d: %s", id, d)
		}
	}

	return ""
}

// servedDiff is how e, the entry a client holds of node nv, differs from
// what the State stores and cfg fixed, on the fields no model judge
// reads. self says whether it is the client's own entry, which carries
// the baseline capabilities; a peer's entry carries no endpoints and no
// home DERP once expired.
func servedDiff(cfg *types.Config, dns types.DNSView, cv tailcfg.CapabilityVersion, e tailcfg.NodeView, nv types.NodeView, self bool) string {
	if e.StableID() != nv.ID().StableID() {
		return fmt.Sprintf("stable ID %q, its ID's %q", e.StableID(), nv.ID().StableID())
	}

	fqdn, err := nv.GetFQDN(dns.BaseDomain())
	if err != nil {
		return fmt.Sprintf("no name: %v", err)
	}

	if e.Name() != fqdn {
		return fmt.Sprintf("name %q, the FQDN of its given name %q", e.Name(), fqdn)
	}

	if !e.Created().Equal(nv.CreatedAt().UTC()) {
		return fmt.Sprintf("created %s, the store %s", e.Created(), nv.CreatedAt().UTC())
	}

	// A peer entry carries a LastSeen only when the render that reached
	// the client sent it whole — the patch that marks it offline carries
	// none — and the store's own moves with every further report of it,
	// so what it holds is only held to be a real time, never the zero
	// time. An own entry never carries one.
	if seen := e.LastSeen(); !self && seen.Valid() && seen.Get().IsZero() {
		return "last seen the zero time"
	}

	endpoints, derp := nv.Endpoints().AsSlice(), tailcfg.DERPRegionID(0)

	if nv.Hostinfo().Valid() && nv.Hostinfo().NetInfo().Valid() {
		derp = nv.Hostinfo().NetInfo().PreferredDERP()
	}

	if !self && nv.IsExpired() {
		endpoints, derp = nil, 0
	}

	if !slices.Equal(e.Endpoints().AsSlice(), endpoints) {
		return fmt.Sprintf("endpoints %v, the store %v", e.Endpoints().AsSlice(), endpoints)
	}

	if e.HomeDERP() != derp {
		return fmt.Sprintf("home DERP %d, the store %d", e.HomeDERP(), derp)
	}

	if !self {
		// A peer's entry is rendered for the version its viewer speaks,
		// and carries only what clients read of it: its source stamps and,
		// for an approved exit node, the exit-node suggestion — none with
		// values, which ride the filter the viewer holds.
		if want := min(max(cv, capver.MinSupportedCapabilityVersion), tailcfg.CurrentCapabilityVersion); e.Cap() != want {
			return fmt.Sprintf("rendered for capability version %d, its viewer speaks %d", e.Cap(), want)
		}

		for c, vs := range e.CapMap().All() {
			if vs.Len() > 0 {
				return fmt.Sprintf("capability %s with %d values, a peer's entry carries none", c, vs.Len())
			}

			if c != nodecap.SuggestExitNode && !strings.Contains(string(c), strings.TrimPrefix(policymodel.StampPrefix, "https://")) {
				return fmt.Sprintf("capability %s, which a peer's entry does not carry", c)
			}
		}

		return peerHostinfoDiff(e.Hostinfo(), nv.Hostinfo())
	}

	// The baseline capabilities an own entry carries whatever the policy
	// grants, headscale having no user roles.
	caps := e.CapMap()

	for _, c := range []nodecap.Cap{nodecap.SSH, nodecap.SSHEnvironmentVariables} {
		if !caps.Contains(c) {
			return fmt.Sprintf("no %s capability", c)
		}
	}

	if got := caps.Contains(nodecap.FileSharing); got != cfg.Taildrop.Enabled {
		return fmt.Sprintf("file sharing %t, the config %t", got, cfg.Taildrop.Enabled)
	}

	_, certDomain := nv.CertDomain(dns)

	if got := caps.Contains(nodecap.HTTPS); got != certDomain {
		return fmt.Sprintf("HTTPS %t, its certificate domain %t", got, certDomain)
	}

	wantUpdate := tailcfg.RawMessage(strconv.FormatBool(cfg.AutoUpdate.Enabled))
	if got, ok := caps.GetOk(nodecap.DefaultAutoUpdate); !ok || got.Len() != 1 || got.At(0) != wantUpdate {
		return fmt.Sprintf("default auto-update %v, the config %t", got, cfg.AutoUpdate.Enabled)
	}

	return ""
}

// peerHostinfoDiff is how the hostinfo e carries of its node differs
// from what the node reported and a peer may see of it: the PeerAPI DNS
// service is its client's own, so a peer's entry leaves it out.
func peerHostinfoDiff(e, hi tailcfg.HostinfoView) string {
	if !hi.Valid() || !e.Valid() {
		return ""
	}

	if e.Hostname() != hi.Hostname() || e.OS() != hi.OS() {
		return fmt.Sprintf("hostname %q OS %q, the node reported %q and %q", e.Hostname(), e.OS(), hi.Hostname(), hi.OS())
	}

	services := slices.DeleteFunc(hi.Services().AsSlice(), func(s tailcfg.Service) bool { return s.Proto == tailcfg.PeerAPIDNS })
	if !slices.EqualFunc(e.Services().AsSlice(), services, func(a, b tailcfg.Service) bool { return reflect.DeepEqual(a, b) }) {
		return fmt.Sprintf("services %s, the node reported %s", policymodel.JSON(e.Services().AsSlice()), policymodel.JSON(services))
	}

	if !slices.Equal(e.SSH_HostKeys().AsSlice(), hi.SSH_HostKeys().AsSlice()) {
		return fmt.Sprintf("SSH host keys %v, the node reported %v", e.SSH_HostKeys().AsSlice(), hi.SSH_HostKeys().AsSlice())
	}

	return ""
}

// storedDiff is how got, as production holds it, differs from tn, model
// node n built, and from how it joined.
func storedDiff(got, tn *types.Node, n policymodel.Node, j Joined) string {
	var out []string

	differ := func(what string, have, want any) {
		out = append(out, fmt.Sprintf("%s %v, the model %v", what, have, want))
	}

	addr := func(a *netip.Addr) netip.Addr {
		if a == nil {
			return netip.Addr{}
		}

		return *a
	}

	if addr(got.IPv4) != n.V4 || addr(got.IPv6) != n.V6 {
		differ("addresses", []netip.Addr{addr(got.IPv4), addr(got.IPv6)}, []netip.Addr{n.V4, n.V6})
	}

	if tags := slices.Sorted(slices.Values(got.Tags)); !slices.Equal(tags, tn.Tags) {
		differ("tags", tags, tn.Tags)
	}

	user := func(u *uint) uint {
		if u == nil {
			return 0
		}

		return *u
	}

	if user(got.UserID) != n.User {
		differ("user", user(got.UserID), n.User)
	}

	sorted := func(ps []netip.Prefix) []netip.Prefix {
		return slices.SortedFunc(slices.Values(ps), netip.Prefix.Compare)
	}

	if a, b := sorted(got.AnnouncedRoutes()), sorted(tn.Hostinfo.RoutableIPs); !slices.Equal(a, b) {
		differ("announced", a, b)
	}

	if a, b := sorted(got.ApprovedRoutes), sorted(tn.ApprovedRoutes); !slices.Equal(a, b) {
		differ("approved", a, b)
	}

	if a, b := sorted(got.AutoApprovedRoutes), sorted(tn.AutoApprovedRoutes); !slices.Equal(a, b) {
		differ("auto-approved", a, b)
	}

	client := func(hi *tailcfg.Hostinfo) string {
		if hi == nil {
			return "none"
		}

		return fmt.Sprintf("go=%q ipn=%q app=%q connector=%v", hi.GoVersion, hi.IPNVersion, hi.App, hi.AppConnector)
	}

	if a, b := client(got.Hostinfo), client(tn.Hostinfo); a != b {
		differ("client", a, b)
	}

	if got.IsExpired() != n.Expired {
		differ("expired", got.IsExpired(), n.Expired)
	}

	if online := !n.Offline && !n.Expired; got.Online() != online {
		differ("online", got.Online(), online)
	}

	if got.RegisterMethod != j.Method || got.Ephemeral != j.Ephemeral {
		differ("registration", fmt.Sprintf("%s ephemeral=%t", got.RegisterMethod, got.Ephemeral), fmt.Sprintf("%s ephemeral=%t (as it joined)", j.Method, j.Ephemeral))
	}

	return strings.Join(out, "; ")
}

// rowDiff is how row, as the database holds it, differs from n in memory
// on the columns a write persists; when it was last seen rides along with
// the next write that persists anything.
func rowDiff(row, n *types.Node) string {
	var out []string

	differ := func(what string, have, want any) {
		out = append(out, fmt.Sprintf("%s %v, in memory %v", what, have, want))
	}

	str := func(a *netip.Addr) string {
		if a == nil {
			return "none"
		}

		return a.String()
	}

	at := func(t *time.Time) string {
		if t == nil {
			return "never"
		}

		return t.UTC().Format(time.RFC3339Nano)
	}

	user := func(u *uint) string {
		if u == nil {
			return "none"
		}

		return strconv.FormatUint(uint64(*u), 10)
	}

	cols := []struct {
		name       string
		have, want string
	}{
		{"machine key", row.MachineKey.String(), n.MachineKey.String()},
		{"node key", row.NodeKey.String(), n.NodeKey.String()},
		{"disco key", row.DiscoKey.String(), n.DiscoKey.String()},
		{"endpoints", fmt.Sprint(row.Endpoints), fmt.Sprint(n.Endpoints)},
		{"addresses", str(row.IPv4) + " " + str(row.IPv6), str(n.IPv4) + " " + str(n.IPv6)},
		{"hostname", row.Hostname, n.Hostname},
		{"given name", row.GivenName, n.GivenName},
		{"user", user(row.UserID), user(n.UserID)},
		{"register method", row.RegisterMethod, n.RegisterMethod},
		{"tags", fmt.Sprint([]string(row.Tags)), fmt.Sprint([]string(n.Tags))},
		{"expiry", at(row.Expiry), at(n.Expiry)},
		{"approved", fmt.Sprint([]netip.Prefix(row.ApprovedRoutes)), fmt.Sprint([]netip.Prefix(n.ApprovedRoutes))},
		{"auto-approved", fmt.Sprint([]netip.Prefix(row.AutoApprovedRoutes)), fmt.Sprint([]netip.Prefix(n.AutoApprovedRoutes))},
		{"ephemeral", strconv.FormatBool(row.Ephemeral), strconv.FormatBool(n.Ephemeral)},
	}

	for _, c := range cols {
		if c.have != c.want {
			differ(c.name, c.have, c.want)
		}
	}

	if !row.Hostinfo.Equal(n.Hostinfo) {
		differ("hostinfo", policymodel.JSON(row.Hostinfo), policymodel.JSON(n.Hostinfo))
	}

	return strings.Join(out, "; ")
}

// ElectionNodes is what the documented election reads of each node snap
// holds: its routes, whether it is online and unexpired, and the HA
// prober's mark.
func ElectionNodes(snap *state.Snapshot) ([]policymodel.RefNode, map[types.NodeID]bool) {
	var (
		nodes     []policymodel.RefNode
		unhealthy = map[types.NodeID]bool{}
	)

	for _, nv := range snap.ListNodes().All() {
		n := nv.AsStruct()
		nodes = append(nodes, policymodel.RefNode{
			ID: n.ID, Tags: n.Tags, Announced: n.AnnouncedRoutes(), Approved: n.ApprovedRoutes,
			Unavailable: !n.Online() || n.IsExpired(),
		})

		if n.Unhealthy {
			unhealthy[n.ID] = true
		}
	}

	return nodes, unhealthy
}
