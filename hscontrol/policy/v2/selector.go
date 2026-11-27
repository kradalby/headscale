package v2

import (
	"cmp"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/types"
)

// SelectorKind is what a selector names. Identity kinds name nodes, by
// who owns them or how they are tagged, so their members move as nodes
// come and go; address kinds name addresses the policy writes down, and
// hold no nodes.
type SelectorKind uint8

const (
	// SelectorUser is a user@ token: the untagged nodes of the one user it
	// resolves to, see [Username.resolveUser].
	SelectorUser SelectorKind = iota + 1
	// SelectorDomain is user:*@domain: the untagged nodes of every user
	// whose e-mail is in the domain.
	SelectorDomain
	// SelectorGroup is group:name: the untagged nodes of its users.
	SelectorGroup
	// SelectorTag is tag:name: the nodes carrying the tag.
	SelectorTag
	// SelectorMember is autogroup:member: every untagged node.
	SelectorMember
	// SelectorTagged is autogroup:tagged: every tagged node.
	SelectorTagged
	// SelectorSelf is autogroup:self. It has no members of its own: it
	// makes every user's untagged nodes an owner role, see [OwnerRole].
	SelectorSelf

	// SelectorWildcard is *.
	SelectorWildcard
	// SelectorHost is a name from the policy's hosts.
	SelectorHost
	// SelectorPrefix is an address or prefix.
	SelectorPrefix
	// SelectorInternet is autogroup:internet.
	SelectorInternet
	// SelectorDangerAll is autogroup:danger-all.
	SelectorDangerAll
	// SelectorUnresolvable is an alias no compile resolves to anything,
	// such as autogroup:nonroot outside SSH users; validation keeps it out
	// of sources and destinations.
	SelectorUnresolvable
)

// HoldsNodes reports whether selectors of kind k have nodes as members.
// autogroup:self does not: its members are per owner.
func (k SelectorKind) HoldsNodes() bool { return k >= SelectorUser && k <= SelectorTagged }

func (k SelectorKind) String() string {
	switch k {
	case SelectorUser:
		return "user"
	case SelectorDomain:
		return "domain"
	case SelectorGroup:
		return "group"
	case SelectorTag:
		return "tag"
	case SelectorMember:
		return "member"
	case SelectorTagged:
		return "tagged"
	case SelectorSelf:
		return "self"
	case SelectorWildcard:
		return "wildcard"
	case SelectorHost:
		return "host"
	case SelectorPrefix:
		return "prefix"
	case SelectorInternet:
		return "internet"
	case SelectorDangerAll:
		return "danger-all"
	case SelectorUnresolvable:
		return "unresolvable"
	}

	return "unknown"
}

// SelectorID is a selector's index in its [SelectorTable]. It means
// something only together with that table.
type SelectorID uint32

// Selector is one alias the policy names as a source, a destination or a
// via tag, as its kind and the policy's spelling of it.
type Selector struct {
	ID   SelectorID
	Kind SelectorKind
	Name string

	// alias is the parsed alias, for resolving; any occurrence serves, as
	// equal names parse to equal aliases.
	alias Alias
}

// SelectorTable is the set of selectors a policy names, which are the
// aliases written in its ACL sources and destinations, its grant sources,
// destinations and via tags, and its SSH sources and destinations; plus *
// for a policy with neither ACLs nor grants, which compiles to allow-all.
// Nothing else is collected: not nodeAttrs targets, tag owners or
// auto-approvers, which the compile still resolves to addresses itself;
// not group members or host prefixes, which are definitions the user sets
// and resolution read; not the policy's tests, which are run against the
// compile. [AuditMembership] holds the table to that by walking the
// parsed policy independently.
//
// It depends on the document only, and is kept by identity while the names
// stay, so whatever was built from it, role sets included, stays valid
// across edits that move rules but name nothing new.
type SelectorTable struct {
	// id identifies the table in the role sets built from it.
	id   uint64
	sels []Selector

	byName map[string]SelectorID
	tags   map[string]SelectorID
	// users are the selectors naming nodes by their user: users, domains
	// and groups.
	users []SelectorID

	member, tagged SelectorID
	hasMember      bool
	hasTagged      bool
	self           bool
}

var selectorTables atomic.Uint64

// Len returns the number of selectors.
func (t *SelectorTable) Len() int { return len(t.sels) }

// Selectors returns every selector, in ID order. It is shared.
func (t *SelectorTable) Selectors() []Selector { return t.sels }

// Selector returns the selector with id.
func (t *SelectorTable) Selector(id SelectorID) Selector { return t.sels[id] }

// Lookup returns the selector spelled name. The parser decides an alias's
// kind from its spelling, so a name is never two kinds.
func (t *SelectorTable) Lookup(name string) (Selector, bool) {
	id, ok := t.byName[name]
	if !ok {
		return Selector{}, false
	}

	return t.sels[id], true
}

// Self reports whether the policy names autogroup:self, which gives every
// user with untagged nodes an owner role.
func (t *SelectorTable) Self() bool { return t.self }

// sameSelectors reports whether t and o name the same selectors, so
// their IDs mean the same.
func (t *SelectorTable) sameSelectors(o *SelectorTable) bool {
	return slices.EqualFunc(t.sels, o.sels, func(a, b Selector) bool { return a.Kind == b.Kind && a.Name == b.Name })
}

// selectorKind returns the kind of a.
func selectorKind(a Alias) SelectorKind {
	switch a := a.(type) {
	case *Username:
		if strings.HasPrefix(string(*a), "user:*@") {
			return SelectorDomain
		}

		return SelectorUser
	case *Group:
		return SelectorGroup
	case *Tag:
		return SelectorTag
	case *AutoGroup:
		switch *a {
		case AutoGroupMember:
			return SelectorMember
		case AutoGroupTagged:
			return SelectorTagged
		case AutoGroupSelf:
			return SelectorSelf
		case AutoGroupInternet:
			return SelectorInternet
		case AutoGroupDangerAll:
			return SelectorDangerAll
		case AutoGroupNonRoot:
		}
	case Asterix:
		return SelectorWildcard
	case *Host:
		return SelectorHost
	case *Prefix:
		return SelectorPrefix
	}

	return SelectorUnresolvable
}

// newSelectorTable collects the selectors pol names; see [SelectorTable]
// for what that covers.
func newSelectorTable(pol *Policy) *SelectorTable {
	named := map[string]Alias{}

	add := func(a Alias) {
		if a == nil {
			return
		}

		if _, ok := named[a.String()]; !ok {
			named[a.String()] = a
		}
	}

	if pol == nil || pol.ACLs == nil && pol.Grants == nil {
		add(Wildcard)
	}

	if pol != nil {
		for _, acl := range pol.ACLs {
			for _, src := range acl.Sources {
				add(src)
			}

			for _, dst := range acl.Destinations {
				add(dst.Alias)
			}
		}

		for _, grant := range pol.Grants {
			for _, src := range grant.Sources {
				add(src)
			}

			for _, dst := range grant.Destinations {
				add(dst)
			}

			for _, tag := range grant.Via {
				add(new(tag))
			}
		}

		for _, ssh := range pol.SSHs {
			for _, src := range ssh.Sources {
				add(src)
			}

			for _, dst := range ssh.Destinations {
				add(dst)
			}
		}
	}

	t := &SelectorTable{
		id:     selectorTables.Add(1),
		sels:   make([]Selector, 0, len(named)),
		byName: make(map[string]SelectorID, len(named)),
		tags:   map[string]SelectorID{},
	}

	for name, a := range named {
		t.sels = append(t.sels, Selector{Kind: selectorKind(a), Name: name, alias: a})
	}

	// By kind, then name: equal documents number their selectors alike.
	slices.SortFunc(t.sels, func(a, b Selector) int {
		return cmp.Or(cmp.Compare(a.Kind, b.Kind), strings.Compare(a.Name, b.Name))
	})

	for i := range t.sels {
		id := SelectorID(i) //nolint:gosec // a policy names far fewer than 2^32 aliases
		s := &t.sels[i]
		s.ID = id
		t.byName[s.Name] = id

		switch s.Kind {
		case SelectorUser, SelectorDomain, SelectorGroup:
			t.users = append(t.users, id)
		case SelectorTag:
			t.tags[s.Name] = id
		case SelectorMember:
			t.member, t.hasMember = id, true
		case SelectorTagged:
			t.tagged, t.hasTagged = id, true
		case SelectorSelf:
			t.self = true
		case SelectorWildcard, SelectorHost, SelectorPrefix, SelectorInternet, SelectorDangerAll, SelectorUnresolvable:
		}
	}

	return t
}

// Selectors is a parsed policy's selector table, with the policy its user
// selectors and hosts are defined by. Neither users nor nodes reach it.
type Selectors struct {
	table *SelectorTable
	pol   *Policy
}

// SelectorsFor returns the selectors of the policy pm compiled, the one in
// force: a compile that failed keeps serving the last good one, and so do
// its selectors. It returns prev while pm compiled the policy prev holds,
// which a compile reuses for as long as the document stays; a policy
// naming the selectors prev names keeps prev's table. A nil pm is no
// policy.
func SelectorsFor(prev *Selectors, pm *PolicyManager) *Selectors {
	var pol *Policy
	if pm != nil {
		pol = pm.pol
	}

	if prev != nil && prev.pol == pol {
		return prev
	}

	return selectorsOf(prev, pol)
}

// NewSelectors parses src into its selectors, for callers without a
// compile. A document that does not parse keeps prev; with no prev it
// gives the selectors of no policy.
func NewSelectors(prev *Selectors, src []byte) (*Selectors, error) {
	pol, err := unmarshalPolicy(src)
	if err != nil {
		if prev == nil {
			prev = selectorsOf(nil, nil)
		}

		return prev, err
	}

	return selectorsOf(prev, pol), nil
}

func selectorsOf(prev *Selectors, pol *Policy) *Selectors {
	table := newSelectorTable(pol)
	if prev != nil && prev.table.sameSelectors(table) {
		table = prev.table
	}

	return &Selectors{table: table, pol: pol}
}

// Describes reports whether s holds the policy pm compiled.
func (s *Selectors) Describes(pm *PolicyManager) bool {
	if pm == nil {
		return s.pol == nil
	}

	return s.pol == pm.pol
}

// Table returns the selector table.
func (s *Selectors) Table() *SelectorTable { return s.table }

// UserSets holds, for each user selector of a table, the users it names
// among a user list: a user@ token the one user it resolves to, a domain
// every user of the domain, a group the users its members name. It reads
// the document's group definitions and the users, never nodes.
type UserSets struct {
	table *SelectorTable
	// bySel holds each selector's user IDs, sorted; nil for selectors
	// that name no users.
	bySel [][]uint
	// byUser is bySel inverted: the user selectors naming each user, in
	// ID order. A Map, so a reader finds which users a change moved.
	byUser *graph.Map[uint, []SelectorID]
}

// NewUserSets resolves the user selectors of sel against users. It
// returns prev when every selector names the users it named in prev, so
// a user added or renamed outside every selector is no change.
func NewUserSets(prev *UserSets, sel *Selectors, users []types.User) *UserSets {
	t := sel.table
	bySel := make([][]uint, t.Len())

	for _, id := range t.users {
		s := t.sels[id]

		switch a := s.alias.(type) {
		case *Username:
			bySel[id] = namedUsers(a, users)
		case *Group:
			var ids []uint

			if sel.pol != nil {
				for _, member := range sel.pol.Groups[*a] {
					ids = append(ids, namedUsers(&member, users)...)
				}
			}

			slices.Sort(ids)
			bySel[id] = slices.Compact(ids)
		}
	}

	if prev != nil && prev.table == t && slices.EqualFunc(prev.bySel, bySel, slices.Equal[[]uint]) {
		return prev
	}

	inverted := map[uint][]SelectorID{}

	for id, uids := range bySel {
		for _, uid := range uids {
			inverted[uid] = append(inverted[uid], SelectorID(id)) //nolint:gosec // bounded by the table
		}
	}

	var byUser *graph.Map[uint, []SelectorID]

	if prev != nil && prev.table == t {
		e := prev.byUser.Edit()

		for uid := range prev.byUser.All() {
			if _, ok := inverted[uid]; !ok {
				e.Delete(uid)
			}
		}

		for uid, sels := range inverted {
			e.Set(uid, sels)
		}

		byUser = e.Done()
	} else {
		byUser = graph.NewMap(slices.Equal[[]SelectorID], inverted)
	}

	return &UserSets{table: t, bySel: bySel, byUser: byUser}
}

// Table returns the table the sets were resolved for.
func (us *UserSets) Table() *SelectorTable { return us.table }

// Users returns the IDs of the users selector id names, sorted. It is
// shared.
func (us *UserSets) Users(id SelectorID) []uint { return us.bySel[id] }

// namedUsers returns the IDs of the users u names, as [Username.resolve]
// picks them: every user of a user:*@ domain, by the e-mail after its last
// @ and ignoring case; otherwise the one user [Username.resolveUser]
// returns, and nobody when it finds none or several.
func namedUsers(u *Username, users types.Users) []uint {
	if domain, ok := strings.CutPrefix(string(*u), "user:*@"); ok {
		var ids []uint

		for _, user := range users {
			if _, d, found := strings.CutLast(user.Email, "@"); found && strings.EqualFold(d, domain) {
				ids = append(ids, user.ID)
			}
		}

		slices.Sort(ids)

		return slices.Compact(ids)
	}

	user, err := u.resolveUser(users)
	if err != nil {
		return nil
	}

	return []uint{user.ID}
}
