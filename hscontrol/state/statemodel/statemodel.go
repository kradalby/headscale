// Package statemodel holds what headscale's State stores, and what its
// clients are served, to policymodel's model: the judges that read
// production types, which every level of the system below the policy
// shares. policymodel imports none of it, which keeps it an oracle.
package statemodel

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy/policymodel"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
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
