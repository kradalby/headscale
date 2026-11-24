package v2

import (
	"cmp"
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unique"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
	"go4.org/netipx"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/views"
)

// roleKind says what a [Role] is membership of.
type roleKind uint8

const (
	roleSelector roleKind = iota
	roleOwner

	// Side atoms, held in a [Sides] set. There roleSelector and roleOwner
	// mean holding an address of a member, or routing over one, which is
	// how the compile's address sets put a node on a rule's side.
	roleNamedPort      // an address of an owner a port self grant's source names
	roleNamedApp       // the same for an app self grant
	roleRouter         // an address of the via router with that node ID
	roleLiteral        // in an address selector's literal, by address or route
	roleAll            // any address or subnet route: inside "*" as written
	roleApproved       // inside an approved subnet route, which "*" sources add
	roleExit           // an exit node
	roleClique         // untagged with that UserID: the same-user clique
	roleHeldNamed      // an owner itself named by its user's self grants
	roleHeldOwner      // an owner holding an address of its user's owners
	roleExitHolder     // an exit owner whose user has a public address
	roleSelfExitLink   // a named owner whose user's port self rules reach the internet
	roleCapExitSeen    // an owner exits list for its own capability to the internet
	roleViaSeen        // an addressed router of that via grant template
	roleRouterOnSrc    // a via router among its own grant's sources
	rolePubRouterOnSrc // such a router with a public address
)

// Role is one membership a node holds: a selector of a table, or, under
// autogroup:self, being one of a user's untagged nodes. Roles order by
// kind, then value.
type Role struct {
	kind  roleKind
	value uint64
}

// SelectorRole is membership of selector id.
func SelectorRole(id SelectorID) Role { return Role{kind: roleSelector, value: uint64(id)} }

// OwnerRole is being an untagged node of the user with uid: what
// autogroup:self names for that user.
func OwnerRole(uid uint) Role { return Role{kind: roleOwner, value: uint64(uid)} }

// Selector returns the selector of a selector role.
func (r Role) Selector() (SelectorID, bool) {
	return SelectorID(r.value), r.kind == roleSelector //nolint:gosec // a selector role holds a SelectorID
}

// Owner returns the user of an owner role.
func (r Role) Owner() (uint, bool) { return uint(r.value), r.kind == roleOwner }

func compareRoles(a, b Role) int {
	return cmp.Or(cmp.Compare(a.kind, b.kind), cmp.Compare(a.value, b.value))
}

func (r Role) String() string {
	name := "selector"
	if int(r.kind) < len(roleKindNames) {
		name = roleKindNames[r.kind]
	}

	return name + ":" + strconv.FormatUint(r.value, 10)
}

var roleKindNames = [...]string{
	roleSelector: "selector", roleOwner: "owner",
	roleNamedPort: "named-port", roleNamedApp: "named-app", roleRouter: "router",
	roleLiteral: "literal", roleAll: "all", roleApproved: "approved", roleExit: "exit",
	roleClique: "clique", roleHeldNamed: "held-named", roleHeldOwner: "held-owner",
	roleExitHolder: "exit-holder", roleSelfExitLink: "self-exit-link", roleCapExitSeen: "cap-exit-seen",
	roleViaSeen: "via-seen", roleRouterOnSrc: "router-on-src", rolePubRouterOnSrc: "pub-router-on-src",
}

// RoleSet is the roles one node holds, interned: two sets are equal
// exactly when they are the same value, so a set compares and keys a map
// by identity. A set is meaningful only with the table it was built from,
// and sets from different tables are never equal.
type RoleSet struct{ h unique.Handle[roleSetKey] }

// roleSetKey is a set's table and its roles, ascending, as a kind byte and
// eight bytes of value each, so byte order is role order.
type roleSetKey struct {
	table uint64
	roles string
}

const roleBytes = 9

func newRoleSet(table uint64, roles []Role) RoleSet {
	slices.SortFunc(roles, compareRoles)
	roles = slices.Compact(roles)

	buf := make([]byte, 0, roleBytes*len(roles))
	for _, r := range roles {
		buf = binary.BigEndian.AppendUint64(append(buf, byte(r.kind)), r.value)
	}

	return RoleSet{h: unique.Make(roleSetKey{table: table, roles: string(buf)})}
}

func (rs RoleSet) packed() string {
	if rs == (RoleSet{}) {
		return ""
	}

	return rs.h.Value().roles
}

// Len returns the number of roles.
func (rs RoleSet) Len() int { return len(rs.packed()) / roleBytes }

// All returns the roles, ascending.
func (rs RoleSet) All() iter.Seq[Role] {
	return func(yield func(Role) bool) {
		p := rs.packed()
		for i := range len(p) / roleBytes {
			if !yield(roleAt(p, i)) {
				return
			}
		}
	}
}

// Roles returns the roles, ascending, in a new slice.
func (rs RoleSet) Roles() []Role { return slices.AppendSeq(make([]Role, 0, rs.Len()), rs.All()) }

// Has reports whether the set holds r.
func (rs RoleSet) Has(r Role) bool {
	p := rs.packed()

	_, found := sort.Find(len(p)/roleBytes, func(i int) int { return compareRoles(r, roleAt(p, i)) })

	return found
}

// roleAt decodes the ith role of a packed set.
func roleAt(packed string, i int) Role {
	at := packed[i*roleBytes : (i+1)*roleBytes]

	var v uint64
	for _, b := range []byte(at[1:]) {
		v = v<<8 | uint64(b)
	}

	return Role{kind: roleKind(at[0]), value: v}
}

func (rs RoleSet) String() string {
	parts := make([]string, 0, rs.Len())
	for r := range rs.All() {
		parts = append(parts, r.String())
	}

	return "{" + strings.Join(parts, " ") + "}"
}

// roleSetOf returns the roles n holds under us. Tagged nodes are owned by
// their tags, so only untagged ones are members, have users or own: and
// only by the user they carry, not the UserID they record, as the
// compile matches users through the loaded user.
func (us *UserSets) roleSetOf(n *types.Node) RoleSet {
	var uid uint
	if n.User != nil {
		uid = n.User.ID
	}

	return us.roleSetFor(n.IsTagged(), views.SliceOf(n.Tags), uid, n.User != nil)
}

// roleSetOfView is roleSetOf for a node's view.
func (us *UserSets) roleSetOfView(n types.NodeView) RoleSet {
	u := n.User()

	var uid uint
	if u.Valid() {
		uid = u.ID()
	}

	return us.roleSetFor(n.IsTagged(), n.Tags(), uid, u.Valid())
}

// roleSetFor is the roles of a node tagged with tags, or untagged with the
// loaded user uid when it has one.
func (us *UserSets) roleSetFor(tagged bool, tags views.Slice[string], uid uint, hasUser bool) RoleSet {
	t := us.table

	var buf [8]Role

	roles := buf[:0]

	if tagged {
		for _, tag := range tags.All() {
			if id, ok := t.tags[tag]; ok {
				roles = append(roles, SelectorRole(id))
			}
		}

		if t.hasTagged {
			roles = append(roles, SelectorRole(t.tagged))
		}
	} else {
		if t.hasMember {
			roles = append(roles, SelectorRole(t.member))
		}

		if hasUser {
			sels, _ := us.byUser.Get(uid)
			for _, id := range sels {
				roles = append(roles, SelectorRole(id))
			}

			if t.self {
				roles = append(roles, OwnerRole(uid))
			}
		}
	}

	return newRoleSet(t.id, roles)
}

// sameRoleFacts reports whether a and b hold the same roles under any
// user sets: they read only tags and the loaded user's ID.
func sameRoleFacts(a, b *types.Node) bool {
	if !slices.Equal(a.Tags, b.Tags) || (a.User == nil) != (b.User == nil) {
		return false
	}

	return a.User == nil || a.User.ID == b.User.ID
}

// NodeMap is the node table as the world holds it.
type NodeMap = graph.Map[types.NodeID, *types.Node]

// Roles holds each node's role set. Updating it recomputes only the nodes
// whose tags or user changed, and those of users whose user selectors
// moved; a write to anything else, an endpoint or Hostinfo, recomputes
// none.
type Roles struct {
	sets  *graph.Map[types.NodeID, RoleSet]
	users *UserSets
	from  *NodeMap

	// computed counts the role sets the update that built this computed.
	computed int
}

// Same reports whether a and b give every node the same role set.
func (r Roles) Same(o Roles) bool { return r.sets == o.sets }

// Of returns the role set of node id.
func (r Roles) Of(id types.NodeID) (RoleSet, bool) { return r.sets.Get(id) }

// Sets returns every node's role set, for a reader to diff two of them.
func (r Roles) Sets() *graph.Map[types.NodeID, RoleSet] { return r.sets }

// All returns every node's role set.
func (r Roles) All() iter.Seq2[types.NodeID, RoleSet] { return r.sets.All() }

// Computed returns how many role sets the update that built r computed.
func (r Roles) Computed() int { return r.computed }

// UserSets returns the user sets r was built from.
func (r Roles) UserSets() *UserSets { return r.users }

// Update returns the role sets of nodes under us, recomputing from r only
// what changed. holders returns, for a user ID, at least every node whose
// loaded user has that ID; nil scans every node.
func (r Roles) Update(us *UserSets, nodes *NodeMap, holders func(uid uint) []types.NodeID) Roles {
	if r.from == nil || r.users == nil || r.users.table != us.table {
		return buildRoles(us, nodes)
	}

	var touched []types.NodeID

	for _, id := range graph.Changes(r.from, nodes) {
		old, had := r.from.Get(id)
		cur, has := nodes.Get(id)

		if had && has && sameRoleFacts(old, cur) {
			continue
		}

		touched = append(touched, id)
	}

	if us != r.users {
		if holders == nil {
			var all []types.NodeID
			for id := range nodes.All() {
				all = append(all, id)
			}

			holders = func(uint) []types.NodeID { return all }
		}

		for _, uid := range graph.Changes(r.users.byUser, us.byUser) {
			for _, id := range holders(uid) {
				// Only an untagged node's role set reads its user's selectors.
				if n, ok := nodes.Get(id); ok && !n.IsTagged() && n.User != nil && n.User.ID == uid {
					touched = append(touched, id)
				}
			}
		}
	}

	if len(touched) == 0 {
		return Roles{sets: r.sets, users: us, from: nodes}
	}

	slices.Sort(touched)
	touched = slices.Compact(touched)

	e := r.sets.Edit()
	computed := 0

	for _, id := range touched {
		n, ok := nodes.Get(id)
		if !ok {
			e.Delete(id)

			continue
		}

		e.Set(id, us.roleSetOf(n))

		computed++
	}

	return Roles{sets: e.Done(), users: us, from: nodes, computed: computed}
}

// buildRoles computes every node's role set.
func buildRoles(us *UserSets, nodes *NodeMap) Roles {
	sets := make(map[types.NodeID]RoleSet, nodes.Len())
	for id, n := range nodes.All() {
		sets[id] = us.roleSetOf(n)
	}

	return Roles{sets: graph.NewMap(graph.Same[RoleSet], sets), users: us, from: nodes, computed: len(sets)}
}

// rolesOfViews computes every listed node's role set, for a caller holding
// views rather than the node table; the result cannot be updated.
func rolesOfViews(us *UserSets, list views.Slice[types.NodeView]) Roles {
	sets := make(map[types.NodeID]RoleSet, list.Len())
	for _, n := range list.All() {
		sets[n.ID()] = us.roleSetOfView(n)
	}

	return Roles{sets: graph.NewMap(graph.Same[RoleSet], sets), users: us, computed: len(sets)}
}

// Postings holds, for each role, the nodes holding it: the members of
// each selector, and each owner's untagged nodes. Updating it edits only
// the lists of the roles a node entered or left.
type Postings struct {
	byRole graph.Grouped[types.NodeID, RoleSet, Role]
	table  *SelectorTable
}

// Same reports whether a and b list the same nodes for every role.
func (p Postings) Same(o Postings) bool { return p.byRole.Groups == o.byRole.Groups }

// Nodes returns the nodes holding r, sorted. It is shared.
func (p Postings) Nodes(r Role) []types.NodeID {
	ids, _ := p.byRole.Groups.Get(r)

	return ids
}

// All returns every role held by a node, with its nodes.
func (p Postings) All() iter.Seq2[Role, []types.NodeID] { return p.byRole.Groups.All() }

// Changed returns the roles whose nodes differ between old and p, or all
// when they were built for different tables: a selector role's ID names
// another selector in each, so no role can be compared across them.
func (p Postings) Changed(old Postings) ([]Role, bool) {
	if p.table != old.table {
		return nil, true
	}

	return graph.Changes(old.byRole.Groups, p.byRole.Groups), false
}

// edited returns the roles whose lists the edits from old to p touched,
// possibly with lists changed back, without comparing them; as
// [Postings.Changed] when old is outside p's edit log.
func (p Postings) edited(old Postings) []Role {
	if old.table == p.table {
		if roles, ok := p.byRole.Groups.ChangedSince(old.byRole.Groups); ok {
			return roles
		}
	}

	roles, _ := p.Changed(old)

	return roles
}

// Update returns the postings of roles, moving from p only the nodes
// whose role set changed. A new table starts over: its selector IDs mean
// other selectors.
func (p Postings) Update(roles Roles) Postings {
	// TODO(kradalby): cost/posting-copies: a node entering or leaving a
	// role copies that role's sorted list whole, so a join costs the size
	// of every list it enters (autogroup:member's is the tailnet's); the
	// sides' holder lists and the peer classes' member lists copy the same
	// way. Accepted: one copy per list a node moves in, no work per node.
	// Fixing it takes persistent sets every reader walks instead of a
	// slice: views, peer classes and the hub's sent views. No upstream
	// reference: headscale's own graph.
	prev := p.byRole
	if p.table != roles.users.table {
		prev = graph.Grouped[types.NodeID, RoleSet, Role]{}
	}

	return Postings{
		byRole: graph.GroupBy(prev, roles.sets, func(_ types.NodeID, rs RoleSet) []Role { return rs.Roles() },
			func(was, is RoleSet) bool { return was == is }),
		table: roles.users.table,
	}
}

// SubnetApprovals are the approved subnet routes of every node, which a *
// source adds to its addresses: approved, announced or not, as SaaS keeps
// a route an admin approved after its node withdrew it. They are route
// facts, apart from roles, so only a change of approvals reaches them.
type SubnetApprovals struct {
	byRoute graph.Grouped[types.NodeID, *types.Node, netip.Prefix]
	strs    []string
}

// Same reports whether a and b hold the same routes: the list is kept
// while the routes stay, so its identity says.
func (a SubnetApprovals) Same(b SubnetApprovals) bool {
	return len(a.strs) == len(b.strs) && (len(a.strs) == 0 || &a.strs[0] == &b.strs[0])
}

// Strings returns the routes as the compile writes them: sorted as text,
// each once. It is shared.
func (a SubnetApprovals) Strings() []string { return a.strs }

// Update returns the approvals of nodes, moving only the nodes whose
// approved routes changed since a.
func (a SubnetApprovals) Update(nodes *NodeMap) SubnetApprovals {
	next := graph.GroupBy(a.byRoute, nodes, func(_ types.NodeID, n *types.Node) []netip.Prefix {
		var out []netip.Prefix

		for _, p := range n.ApprovedRoutes {
			if !tsaddr.IsExitRoute(p) {
				out = append(out, p)
			}
		}

		return out
	}, func(was, is *types.Node) bool { return slices.Equal(was.ApprovedRoutes, is.ApprovedRoutes) })

	if a.byRoute.Groups != nil {
		moved := false

		for _, p := range graph.Changes(a.byRoute.Groups, next.Groups) {
			_, was := a.byRoute.Groups.Get(p)
			if _, is := next.Groups.Get(p); was != is {
				moved = true

				break
			}
		}

		if !moved {
			return SubnetApprovals{byRoute: next, strs: a.strs}
		}
	}

	strs := []string{}
	for p := range next.Groups.All() {
		strs = append(strs, p.String())
	}

	slices.Sort(strs)

	return SubnetApprovals{byRoute: next, strs: strs}
}

// approvalsOfViews is [SubnetApprovals.Update] from scratch over views; the
// result cannot be updated.
func approvalsOfViews(list views.Slice[types.NodeView]) SubnetApprovals {
	seen := map[netip.Prefix]struct{}{}

	for _, n := range list.All() {
		for _, p := range n.ApprovedRoutes().All() {
			if !tsaddr.IsExitRoute(p) {
				seen[p] = struct{}{}
			}
		}
	}

	strs := make([]string, 0, len(seen))
	for p := range seen {
		strs = append(strs, p.String())
	}

	slices.Sort(strs)

	return SubnetApprovals{strs: strs}
}

var errMembershipAudit = errors.New("membership differs")

// Membership is the membership of one snapshot, as [AuditMembership]
// checks it.
type Membership struct {
	Selectors *Selectors
	UserSets  *UserSets
	Roles     Roles
	Postings  Postings
	Users     []types.User
	Nodes     *NodeMap

	// Policy is the compile in force. Current reports that it compiled
	// these users and nodes, so what it resolved is the oracle; otherwise,
	// a failed compile having kept an older one, its policy is resolved
	// against them afresh.
	Policy  *PolicyManager
	Current bool

	// TableAudited reports that these Selectors passed the completeness
	// check already: a table and its policy never change, so it holds.
	TableAudited bool
}

// MembershipReport counts what an audit could judge, and how.
type MembershipReport struct {
	// Compiled and Indexed count the identity selectors held against the
	// compile's own resolution: as its alias cache holds it, or, for an
	// alias the compile never resolved, through its indexes. Fresh counts
	// those resolved afresh, when the compile was not current.
	Compiled, Indexed, Fresh int
	// Judged counts the (node, identity selector) pairs decided by the
	// node's own addresses; Relabelled the pairs decided again by a fresh
	// resolution over the nodes relabelled with a unique address each.
	Judged, Relabelled int
}

// AuditMembership checks m against what it must agree with, returning
// the first difference:
//
//   - the selector table holds exactly the aliases an independent walk of
//     the policy finds in the sections in scope ([selectorSections]);
//   - user sets, role sets and postings equal a build from scratch;
//   - every node is in an identity selector's postings exactly when the
//     compile's resolution of it holds the node's own addresses; and
//     exactly when a fresh resolution over the nodes relabelled with a
//     unique address each holds its label;
//   - each owner lists the user's untagged nodes the compile wrote
//     autogroup:self rules for, under self only;
//   - address selectors list no nodes and resolve without users or nodes.
//
// It is for debugging and tests: it costs a build from scratch and two
// resolutions of every selector.
func AuditMembership(m Membership) (MembershipReport, error) {
	var rep MembershipReport

	if m.Policy != nil && !m.Selectors.Describes(m.Policy) {
		return rep, fmt.Errorf("%w: selectors describe another policy than the compile in force", errMembershipAudit)
	}

	if !m.TableAudited {
		err := auditSelectorTable(m.Selectors)
		if err != nil {
			return rep, err
		}
	}

	err := auditRebuild(m)
	if err != nil {
		return rep, err
	}

	return auditResolve(m)
}

// auditRebuild compares the incremental cells with a build from scratch.
// The maps compared are unrelated, so they are compared entry by entry:
// [graph.Changes] would count each as an edit-log miss.
func auditRebuild(m Membership) error {
	fresh := NewUserSets(nil, m.Selectors, m.Users)
	if !slices.EqualFunc(m.UserSets.bySel, fresh.bySel, slices.Equal[[]uint]) {
		return fmt.Errorf("%w: user sets", errMembershipAudit)
	}

	if diff := mapDiff(fresh.byUser, m.UserSets.byUser, slices.Equal[[]SelectorID]); len(diff) > 0 {
		return fmt.Errorf("%w: user sets of users %v", errMembershipAudit, diff)
	}

	want := buildRoles(m.UserSets, m.Nodes)
	if diff := mapDiff(want.sets, m.Roles.sets, graph.Same[RoleSet]); len(diff) > 0 {
		return fmt.Errorf("%w: role sets of nodes %v", errMembershipAudit, diff)
	}

	wantPosts := Postings{}.Update(want)
	if diff := mapDiff(wantPosts.byRole.Groups, m.Postings.byRole.Groups, slices.Equal[[]types.NodeID]); len(diff) > 0 {
		return fmt.Errorf("%w: postings of roles %v", errMembershipAudit, diff)
	}

	return nil
}

// mapDiff returns the keys whose entries differ between a and b.
func mapDiff[K comparable, V any](a, b *graph.Map[K, V], eq func(x, y V) bool) []K {
	var keys []K

	for k, v := range a.All() {
		if w, ok := b.Get(k); !ok || !eq(v, w) {
			keys = append(keys, k)
		}
	}

	for k := range b.All() {
		if _, ok := a.Get(k); !ok {
			keys = append(keys, k)
		}
	}

	return keys
}

// resolver resolves an alias as the oracle of one audit.
type resolver func(Alias) (ResolvedAddresses, error)

// compiledResolver resolves as the compile pm did: from its alias cache,
// which an incremental compile may have carried from an earlier one, or,
// for an alias it never resolved, through its own indexes. It never writes
// to pm, which is shared once published.
func compiledResolver(pm *PolicyManager, rep *MembershipReport) resolver {
	return func(a Alias) (ResolvedAddresses, error) {
		if r, ok := pm.aliases[keyOf(a)]; ok {
			rep.Compiled++

			return r.ips, r.err
		}

		rep.Indexed++

		if pm.resolvedPol == nil {
			return a.Resolve(nil, pm.users, pm.nodes)
		}

		uncached := *pm.resolvedPol
		uncached.aliases = nil

		return uncached.resolveAlias(a, pm.users, pm.nodes)
	}
}

// indexedResolver resolves as a compile from scratch of pol over users and
// nodes would.
func indexedResolver(pol *Policy, users []types.User, nodes views.Slice[types.NodeView]) resolver {
	indexed := pol.withNodesByTag(nodes).withResolvedGroups(users, nodes)
	if indexed != nil {
		indexed.aliases = aliasCache{}
	}

	return func(a Alias) (ResolvedAddresses, error) { return indexed.resolveAlias(a, users, nodes) }
}

// auditResolve holds every selector's postings, node by node, against the
// compile's resolution of its alias.
func auditResolve(m Membership) (MembershipReport, error) {
	var rep MembershipReport

	nvs := nodeViews(m.Nodes)

	resolve := indexedResolver(m.Selectors.pol, m.Users, nvs)
	owners := buildUserNodeIndex(nvs)

	if m.Policy != nil && m.Current {
		resolve, owners = compiledResolver(m.Policy, &rep), m.Policy.userNodeIdx
	}

	// The same nodes, each with a unique address of its own, resolved
	// afresh: postings held to a resolution other than the compile's.
	relabelled, labels := relabel(nvs, m.Nodes)
	resolveRelabelled := indexedResolver(m.Selectors.pol, m.Users, relabelled)

	for _, s := range m.Selectors.table.sels {
		members := m.Postings.Nodes(SelectorRole(s.ID))

		switch {
		case s.Kind.HoldsNodes():
			if m.Policy == nil || !m.Current {
				rep.Fresh++
			}

			want, err := resolve(s.alias)
			if err != nil {
				return rep, fmt.Errorf("%w: resolving %s: %w", errMembershipAudit, s.Name, err)
			}

			err = auditMembers(s, members, nvs, want, &rep.Judged)
			if err != nil {
				return rep, err
			}

			got := postingAddresses(members, m.Nodes)
			if !slices.Equal(resolvedPrefixes(want), got.Prefixes()) {
				return rep, fmt.Errorf("%w: %s %s lists %v, resolves to %v", errMembershipAudit, s.Kind, s.Name, got.Prefixes(), resolvedPrefixes(want))
			}

			wantLabels, err := resolveRelabelled(s.alias)
			if err != nil {
				return rep, fmt.Errorf("%w: resolving %s relabelled: %w", errMembershipAudit, s.Name, err)
			}

			for i, nv := range nvs.All() {
				in := wantLabels != nil && wantLabels.Contains(labels[i])
				if in != slices.Contains(members, nv.ID()) {
					return rep, fmt.Errorf("%w: %s %s: node %d listed %t, resolved %t (relabelled)",
						errMembershipAudit, s.Kind, s.Name, nv.ID(), !in, in)
				}

				rep.Relabelled++
			}
		case s.Kind == SelectorSelf:
		default:
			// Resolve reads neither users nor nodes for an address alias.
			// The compile still writes * as more than its resolution, adding
			// every approved subnet route (buildSrcIPStrings): that is not
			// membership, and no posting holds it.
			bare, bareErr := s.alias.Resolve(m.Selectors.pol, nil, views.Slice[types.NodeView]{})
			got, gotErr := resolve(s.alias)

			if (bareErr == nil) != (gotErr == nil) || !slices.Equal(resolvedPrefixes(bare), resolvedPrefixes(got)) {
				return rep, fmt.Errorf("%w: address selector %s resolves by users or nodes", errMembershipAudit, s.Name)
			}

			if len(members) > 0 {
				return rep, fmt.Errorf("%w: address selector %s lists nodes %v", errMembershipAudit, s.Name, members)
			}
		}
	}

	return rep, auditOwners(m, owners)
}

// auditMembers holds members against want for every node: all of its
// addresses in want or none.
func auditMembers(s Selector, members []types.NodeID, nvs views.Slice[types.NodeView], want ResolvedAddresses, judged *int) error {
	for _, nv := range nvs.All() {
		ips := nv.IPs()
		in := 0

		for _, a := range ips {
			if want != nil && want.Contains(a) {
				in++
			}
		}

		if in != 0 && in != len(ips) {
			return fmt.Errorf("%w: %s %s resolves to some of node %d's addresses", errMembershipAudit, s.Kind, s.Name, nv.ID())
		}

		if listed := slices.Contains(members, nv.ID()); listed != (in > 0) {
			return fmt.Errorf("%w: %s %s: node %d listed %t, resolved %t", errMembershipAudit, s.Kind, s.Name, nv.ID(), listed, in > 0)
		}

		*judged++
	}

	return nil
}

// auditOwners holds the owner postings against owners, the untagged nodes
// of each user autogroup:self rules are written for.
func auditOwners(m Membership, owners userNodeIndex) error {
	for r, ids := range m.Postings.All() {
		uid, ok := r.Owner()
		if !ok {
			continue
		}

		if !m.Selectors.table.self {
			return fmt.Errorf("%w: owner role %d without autogroup:self", errMembershipAudit, uid)
		}

		if !slices.Equal(ids, viewIDs(owners[uid])) {
			return fmt.Errorf("%w: owner %d lists %v, owns %v", errMembershipAudit, uid, ids, viewIDs(owners[uid]))
		}
	}

	if m.Selectors.table.self {
		for uid, owned := range owners {
			if len(owned) > 0 && len(m.Postings.Nodes(OwnerRole(uid))) == 0 {
				return fmt.Errorf("%w: owner %d of %v has no posting", errMembershipAudit, uid, viewIDs(owned))
			}
		}
	}

	return nil
}

// relabelPrefix is where relabelled nodes get their one address: a
// documentation prefix no tailnet address is in.
var relabelPrefix = netip.MustParsePrefix("2001:db8:ffff::/48")

// relabel returns copies of nvs, nodes of nodes, each with one address of
// its own and no other, and those addresses, in order. The copies are
// shallow: nothing reads them but resolution.
func relabel(nvs views.Slice[types.NodeView], nodes *NodeMap) (views.Slice[types.NodeView], []netip.Addr) {
	out := make([]types.NodeView, 0, nvs.Len())
	labels := make([]netip.Addr, 0, nvs.Len())
	copies := make([]types.Node, nvs.Len())

	base := relabelPrefix.Addr().As16()

	for i, nv := range nvs.All() {
		a := base
		binary.BigEndian.PutUint64(a[8:], uint64(i)+1) //nolint:gosec // an index
		labels = append(labels, netip.AddrFrom16(a))

		n, _ := nodes.Get(nv.ID())
		copies[i] = *n
		copies[i].IPv4, copies[i].IPv6 = nil, &labels[i]

		out = append(out, copies[i].View())
	}

	return views.SliceOf(out), labels
}

// selectorSections decides, for every exported field of [Policy], whether
// the aliases written under it are selectors: those the compile resolves
// into filter rules, via steering or SSH rules, which M2 and M3 move onto
// roles. A field this does not name fails the audit, so a new policy
// section needs a decision.
var selectorSections = map[string]bool{
	"ACLs":   true,
	"Grants": true,
	"SSHs":   true,

	// Definitions, not uses: user sets read group members, resolution reads
	// host prefixes.
	"Groups": false,
	"Hosts":  false,
	// The compile resolves these to addresses itself, and matches nodes by
	// address; moving them onto roles is later work.
	"TagOwners":     false,
	"AutoApprovers": false,
	"NodeAttrs":     false,
	// Run against the compile, not compiled.
	"Tests":    false,
	"SSHTests": false,
	// No aliases.
	"RandomizeClientPort": false,
	"DERPMap":             false,
}

var aliasType = reflect.TypeFor[Alias]()

// policyAliases walks pol by reflection, sharing nothing with the selector
// table's collector, and returns the aliases written under each exported
// field of pol, wherever they sit in it.
func policyAliases(pol *Policy) map[string][]Alias {
	out := map[string][]Alias{}
	if pol == nil {
		return out
	}

	v := reflect.ValueOf(pol).Elem()

	for i := range v.NumField() {
		f := v.Type().Field(i)
		if !f.IsExported() {
			continue
		}

		out[f.Name] = nil

		walkAliases(v.Field(i), func(a Alias) { out[f.Name] = append(out[f.Name], a) })
	}

	return out
}

func walkAliases(v reflect.Value, visit func(Alias)) {
	if !v.IsValid() {
		return
	}

	if a, ok := asAlias(v); ok {
		visit(a)

		return
	}

	switch v.Kind() { //nolint:exhaustive // only containers hold aliases; the rest are leaves
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			walkAliases(v.Elem(), visit)
		}
	case reflect.Struct:
		for i := range v.NumField() {
			if v.Type().Field(i).IsExported() {
				walkAliases(v.Field(i), visit)
			}
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			walkAliases(v.Index(i), visit)
		}
	case reflect.Map:
		for it := v.MapRange(); it.Next(); {
			walkAliases(it.Key(), visit)
			walkAliases(it.Value(), visit)
		}
	}
}

// asAlias returns v as an alias when its type, or a pointer to it, is one.
// A struct embedding Alias, such as [AliasWithPorts], wraps one: it is
// walked, not taken.
func asAlias(v reflect.Value) (Alias, bool) {
	t := v.Type()

	switch {
	case t.Kind() == reflect.Interface, t.Kind() == reflect.Pointer && v.IsNil():
		return nil, false
	case t.Kind() == reflect.Struct && embedsAlias(t):
		return nil, false
	case t.Implements(aliasType):
		return reflect.TypeAssert[Alias](v)
	case reflect.PointerTo(t).Implements(aliasType):
		p := reflect.New(t)
		p.Elem().Set(v)

		return reflect.TypeAssert[Alias](p)
	}

	return nil, false
}

func embedsAlias(t reflect.Type) bool {
	for f := range t.Fields() {
		if f.Anonymous && f.Type == aliasType {
			return true
		}
	}

	return false
}

// auditSelectorTable checks that sel's table holds exactly the aliases
// [policyAliases] finds in the sections [selectorSections] puts in scope,
// each as the type the policy parsed it to; plus * for a policy without
// ACLs or grants, which the compile treats as allow-all.
func auditSelectorTable(sel *Selectors) error {
	want := map[string]string{}

	for section, aliases := range policyAliases(sel.pol) {
		in, known := selectorSections[section]
		if !known {
			return fmt.Errorf("%w: policy section %s is neither in nor out of the selector table's scope", errMembershipAudit, section)
		}

		if !in {
			continue
		}

		for _, a := range aliases {
			want[a.String()] = fmt.Sprintf("%T", a)
		}
	}

	if sel.pol == nil || sel.pol.ACLs == nil && sel.pol.Grants == nil {
		want[Wildcard.String()] = fmt.Sprintf("%T", Wildcard)
	}

	for name, typ := range want {
		s, ok := sel.table.Lookup(name)
		if !ok {
			return fmt.Errorf("%w: the policy names %s, the selector table lacks it", errMembershipAudit, name)
		}

		if got := fmt.Sprintf("%T", s.alias); got != typ {
			return fmt.Errorf("%w: selector %s is a %s, the policy wrote a %s", errMembershipAudit, name, got, typ)
		}
	}

	for _, s := range sel.table.sels {
		if _, ok := want[s.Name]; !ok {
			return fmt.Errorf("%w: the selector table holds %s, which no section in scope names", errMembershipAudit, s.Name)
		}
	}

	return nil
}

// nodeViews returns the views of nodes, sorted by ID.
func nodeViews(nodes *NodeMap) views.Slice[types.NodeView] {
	out := make([]types.NodeView, 0, nodes.Len())
	for _, n := range nodes.All() {
		out = append(out, n.View())
	}

	slices.SortFunc(out, func(a, b types.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })

	return views.SliceOf(out)
}

// resolvedPrefixes returns r's addresses; r may be nil.
func resolvedPrefixes(r ResolvedAddresses) []netip.Prefix {
	if r == nil {
		return nil
	}

	return r.Prefixes()
}

func viewIDs(nvs []types.NodeView) []types.NodeID {
	ids := make([]types.NodeID, 0, len(nvs))
	for _, nv := range nvs {
		ids = append(ids, nv.ID())
	}

	slices.Sort(ids)

	return ids
}

// postingAddresses returns the addresses of the nodes ids.
func postingAddresses(ids []types.NodeID, nodes *NodeMap) *netipx.IPSet {
	var b netipx.IPSetBuilder

	for _, id := range ids {
		if n, ok := nodes.Get(id); ok {
			n.AppendToIPSet(&b)
		}
	}

	set, _ := b.IPSet()

	return set
}
