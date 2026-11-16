package v2

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

// Templates are the policy's filter rules before any alias resolves: each
// grant, ACLs turned into grants as the compile turns them, with its
// sources and destinations named by selector and everything else the
// compile decides per grant written down. They read the policy document
// only. Users and nodes reach a filter through postings, see [Expansion].
type Templates struct {
	sel *Selectors

	// literals holds what each address selector resolves to, by selector
	// ID; identity selectors resolve through their postings instead.
	literals []literal
	grants   []*GrantTemplate

	// err records a grant naming an alias the table lacks, which only a
	// table that does not describe the policy can cause.
	err error

	// plan is what the templates say about sides, built on first use.
	planOnce sync.Once
	plan     *sidePlan
}

// literal is an address selector resolved as the compile resolves it,
// with no users or nodes. err is kept beside a partial result: some of
// the compile's paths use one, others skip it.
type literal struct {
	res ResolvedAddresses
	err error

	// entries are res's strings with their ranges, as destinations.
	entries []literalEntry
}

type literalEntry struct {
	str string
	r   netipx.IPRange
}

// grantKind is the category a grant compiles in, see [grantCategory].
type grantKind uint8

const (
	// grantRegular compiles to the same rules for every node.
	grantRegular grantKind = iota
	// grantSelf adds, per owner, rules to the owner's untagged nodes.
	grantSelf
	// grantVia compiles per via router only.
	grantVia
)

// GrantTemplate is one grant as the compile reads it, a function of the
// grant and the selector table alone, so an edit elsewhere in the document
// keeps it. Its rules, in order: one per ip entry over the destinations
// other than autogroup:self, then the app capability rule and its
// companions; then, per owner the receiver gets them for, the
// autogroup:self rules. A via grant has only one rule per ip entry, on
// each via router.
type GrantTemplate struct {
	kind grantKind
	// none is set when the grant compiles to nothing whatever the nodes:
	// a literally empty source or destination list, or autogroup:self
	// among the sources.
	none bool

	// srcs are the sources, in policy order.
	srcs      []SelectorID
	wildcard  bool
	dangerAll bool

	// dsts are the destinations other than autogroup:self, in policy
	// order; for a via grant, every destination but autogroup:internet.
	dsts []SelectorID
	// dstWildcard is set when * is among dsts: a capability's companion
	// rules then add the approved routes to their sources.
	dstWildcard bool

	ip  []ipRule
	app tailcfg.PeerCapMap

	via []Tag
	// viaClass keeps a via rule apart from every rule but via rules
	// through the same tags when rules merge.
	viaClass    string
	viaInternet bool

	// src is the grant, which reuse across edits compares.
	src Grant
}

// ipRule is one ip entry: its protocols as the wire writes them, and its
// ports.
type ipRule struct {
	proto []int
	ports []tailcfg.PortRange
}

// Selectors returns the selectors the templates were built from.
func (t *Templates) Selectors() *Selectors { return t.sel }

// Grants returns the grant templates, in compile order. They are shared.
func (t *Templates) Grants() []*GrantTemplate { return t.grants }

// Err reports a template naming an alias the selector table lacks.
func (t *Templates) Err() error { return t.err }

func (t *Templates) table() *SelectorTable { return t.sel.table }

// BuildTemplates returns the templates of sel's policy. Given prev, built
// for the same selector table, it keeps each grant template whose grant
// is unchanged; it returns prev itself while sel is the selectors prev
// holds, which a recompile of the same document keeps.
func BuildTemplates(prev *Templates, sel *Selectors) *Templates {
	if prev != nil && prev.sel == sel {
		return prev
	}

	t := &Templates{sel: sel, literals: make([]literal, sel.table.Len())}

	for _, s := range sel.table.sels {
		if !s.Kind.HoldsNodes() {
			t.literals[s.ID] = resolveLiteral(sel.pol, s)
		}
	}

	pol := sel.pol
	if pol == nil || (pol.ACLs == nil && pol.Grants == nil) {
		// The compile allows all when the policy has neither.
		pol = allowAllPolicy()
	}

	reuse := map[string][]*GrantTemplate{}

	if prev != nil && prev.sel.table == sel.table {
		for _, g := range prev.grants {
			if k, ok := grantKey(g.src); ok {
				reuse[k] = append(reuse[k], g)
			}
		}
	}

	for _, g := range pol.allGrants() {
		if k, ok := grantKey(g); ok {
			if kept := reusable(reuse[k], g); kept != nil {
				t.grants = append(t.grants, kept)

				continue
			}
		}

		gt, err := newGrantTemplate(sel.table, g)
		if err != nil && t.err == nil {
			t.err = err
		}

		t.grants = append(t.grants, gt)
	}

	return t
}

// reusable returns a template in candidates built from a grant equal to g.
func reusable(candidates []*GrantTemplate, g Grant) *GrantTemplate {
	for _, c := range candidates {
		if reflect.DeepEqual(c.src, g) {
			return c
		}
	}

	return nil
}

// grantKey buckets grants for reuse; [reusable] decides equality.
func grantKey(g Grant) (string, bool) {
	b, err := json.Marshal(g)

	return string(b), err == nil
}

var errTemplateSelector = errors.New("template names an alias its selector table lacks")

func newGrantTemplate(table *SelectorTable, g Grant) (*GrantTemplate, error) {
	gt := &GrantTemplate{src: g, app: g.App}

	lookup := func(a Alias) (Selector, error) {
		s, ok := table.Lookup(a.String())
		if !ok {
			return Selector{}, fmt.Errorf("%w: %s", errTemplateSelector, a)
		}

		return s, nil
	}

	for _, a := range g.Sources {
		s, err := lookup(a)
		if err != nil {
			return &GrantTemplate{src: g, none: true}, err
		}

		if s.Kind == SelectorSelf {
			// The compile refuses the grant, see errSelfInSources.
			gt.none = true
		}

		gt.srcs = append(gt.srcs, s.ID)
	}

	gt.wildcard = sourcesHaveWildcard(g.Sources)
	gt.dangerAll = sourcesHaveDangerAll(g.Sources)

	for _, ipp := range g.InternetProtocols {
		gt.ip = append(gt.ip, ipRule{proto: ipp.Protocol.toIANAProtocolNumbers(), ports: ipp.Ports})
	}

	// A via grant has no check for empty lists; it compiles to nothing
	// without sources, and to no rule on any router without destinations.
	if g.HasVia() {
		gt.kind = grantVia
		gt.via = g.Via
		gt.viaClass = fmt.Sprintf("via:%v", g.Via)
	} else if len(g.Sources) == 0 || len(g.Destinations) == 0 {
		gt.none = true
	}

	for _, a := range g.Destinations {
		s, err := lookup(a)
		if err != nil {
			return &GrantTemplate{src: g, none: true}, err
		}

		switch {
		case gt.kind == grantVia && s.Kind == SelectorInternet:
			gt.viaInternet = true
		case gt.kind != grantVia && s.Kind == SelectorSelf:
			gt.kind = grantSelf
		default:
			gt.dsts = append(gt.dsts, s.ID)
			gt.dstWildcard = gt.dstWildcard || s.Kind == SelectorWildcard
		}
	}

	return gt, nil
}

// resolveLiteral resolves an address selector, which reads neither users
// nor nodes; pol supplies the hosts.
func resolveLiteral(pol *Policy, s Selector) literal {
	if s.alias == nil {
		return literal{}
	}

	res, err := s.alias.Resolve(pol, nil, views.Slice[types.NodeView]{})

	l := literal{res: res, err: err}
	if res == nil {
		return l
	}

	for _, str := range res.Strings() {
		r, perr := util.ParseIPRange(str)
		if perr != nil {
			// A destination that does not parse reaches nothing.
			continue
		}

		l.entries = append(l.entries, literalEntry{str: str, r: r})
	}

	return l
}

var errTemplatesDiffer = errors.New("templates differ from templates built from scratch")

// AuditTemplates returns how t differs from templates built from scratch
// for the same selectors: a grant template kept across an edit that
// changed what it compiles to.
func AuditTemplates(t *Templates) error {
	if t.err != nil {
		return t.err
	}

	fresh := BuildTemplates(nil, t.sel)

	if len(fresh.grants) != len(t.grants) {
		return fmt.Errorf("%w: %d grants, %d from scratch", errTemplatesDiffer, len(t.grants), len(fresh.grants))
	}

	for i := range t.grants {
		if !reflect.DeepEqual(t.grants[i], fresh.grants[i]) {
			return fmt.Errorf("%w: grant %d", errTemplatesDiffer, i)
		}
	}

	if !reflect.DeepEqual(t.literals, fresh.literals) {
		return fmt.Errorf("%w: literals", errTemplatesDiffer)
	}

	return nil
}
