package policymodel

import (
	"cmp"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"net/netip"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"go4.org/netipx"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
)

const modulePath = "github.com/juanfont/headscale/"

// TestImports keeps the package independent of what its properties check.
// Of headscale it imports only hscontrol/types; nothing it reaches
// through any chain of imports is the compile, the world or the mapper;
// and its own code calls no method of headscale's node and user types,
// several of which evaluate access through the policy matchers. And it
// stays out of the binary: no file outside tests imports it.
func TestImports(t *testing.T) {
	t.Parallel()

	allowed := []string{modulePath + "hscontrol/types", "tailscale.com/", "go4.org/", "pgregory.net/rapid"}
	own := importsOf(t, ".", false)

	for path, imports := range own {
		for _, imp := range imports {
			std := !strings.Contains(strings.Split(imp, "/")[0], ".")
			if !std && !slices.ContainsFunc(allowed, func(a string) bool { return imp == a || strings.HasPrefix(imp, a) && strings.HasSuffix(a, "/") }) {
				t.Errorf("%s imports %s; the model must not share code with what it checks", path, imp)
			}
		}
	}

	forbidden := []string{"hscontrol/policy", "hscontrol/policy/v2", "hscontrol/state", "hscontrol/mapper"}
	for pkg, via := range internalClosure(t, own) {
		if slices.Contains(forbidden, pkg) {
			t.Errorf("the package reaches %s through %s", pkg, via)
		}
	}

	for _, call := range typesMethodCalls(t) {
		t.Errorf("%s calls a method of headscale's node or user types; read their fields", call)
	}

	self, _ := filepath.Abs(".")

	for _, dir := range []string{"../..", "../../../cmd"} {
		for path, imports := range importsOf(t, dir, true) {
			abs, _ := filepath.Abs(filepath.Dir(path))
			if abs != self && slices.Contains(imports, modulePath+"hscontrol/policy/policymodel") {
				t.Errorf("%s imports policymodel; only tests may", path)
			}
		}
	}
}

// importsOf returns the imports of every non-test Go file in dir, and
// below it if deep, by path.
func importsOf(t *testing.T, dir string, deep bool) map[string][]string {
	t.Helper()

	out := map[string][]string{}

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if path != dir && (!deep || d.Name() == "testdata") {
				return filepath.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}

		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			out[path] = append(out[path], p)
		}

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return out
}

// internalClosure returns every headscale package the files reach through
// their imports, each with the chain that reaches it.
func internalClosure(t *testing.T, files map[string][]string) map[string]string {
	t.Helper()

	reached := map[string]string{}

	var visit func(pkg, via string)

	visit = func(pkg, via string) {
		if _, ok := reached[pkg]; ok {
			return
		}

		reached[pkg] = via

		for _, imports := range importsOf(t, filepath.Join("../../..", pkg), false) {
			for _, imp := range imports {
				if next, ok := strings.CutPrefix(imp, modulePath); ok {
					visit(next, via+" -> "+next)
				}
			}
		}
	}

	for _, path := range slices.Sorted(maps.Keys(files)) {
		for _, imp := range files[path] {
			if pkg, ok := strings.CutPrefix(imp, modulePath); ok {
				visit(pkg, filepath.Base(path)+" -> "+pkg)
			}
		}
	}

	return reached
}

// typesMethodCalls returns the calls in the package's own files to a
// method only headscale's node and user types have: their names, less
// those the client's views and this package's own types also have.
func typesMethodCalls(t *testing.T) []string {
	t.Helper()

	methods := func(vs ...any) map[string]bool {
		out := map[string]bool{}

		for _, v := range vs {
			typ := reflect.TypeOf(v)
			for m := range typ.Methods() {
				out[m.Name] = true
			}
		}

		return out
	}

	theirs := methods(&types.Node{}, types.NodeView{}, &types.User{}, types.UserView{}, types.Nodes{}, types.Users{})
	shared := methods(tailcfg.NodeView{}, tailcfg.HostinfoView{}, &tailcfg.Node{}, tailcfg.NodeCapMap{}, tailcfg.PeerCapMap{},
		netip.Addr{}, netip.Prefix{}, &netipx.IPSet{}, &netipx.IPSetBuilder{})

	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")

	var calls []string

	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}

		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv != nil {
				shared[fd.Name.Name] = true
			}
		}

		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && theirs[sel.Sel.Name] && !shared[sel.Sel.Name] {
					calls = append(calls, fmt.Sprintf("%s: %s", fset.Position(c.Pos()), sel.Sel.Name))
				}
			}

			return true
		})
	}

	return calls
}

// TestGeneratorsAreDeterministic: the same seed draws the same case, and
// building it twice gives the same document and nodes. Anything reading
// the clock or a map's order would break both, and with them shrinking.
func TestGeneratorsAreDeterministic(t *testing.T) {
	t.Parallel()

	gen := Scenarios(10)

	for i := range 200 {
		a, b := gen.Example(i), gen.Example(i)
		if !reflect.DeepEqual(a, b) || a.GoString() != b.GoString() {
			t.Fatalf("seed %d drew two scenarios:\n%#v\n%#v", i, a, b)
		}

		for _, w := range a.Worlds() {
			first, second := w.Policy.HuJSON(), w.Policy.HuJSON()
			if string(first) != string(second) {
				t.Fatalf("seed %d: the document differs between writes", i)
			}

			u1, n1 := w.Topology.Build()
			u2, n2 := w.Topology.Build()

			if !reflect.DeepEqual(u1, u2) || !reflect.DeepEqual(n1, n2) {
				t.Fatalf("seed %d: the topology builds differently twice", i)
			}
		}
	}
}

// TestSimplestDrawIsPlain draws from all zeros, which is where shrinking
// heads: it must be the plain case, so a minimised counterexample shows
// only what its failure needs.
func TestSimplestDrawIsPlain(t *testing.T) {
	t.Parallel()

	var got Scenario

	rapid.MakeFuzz(func(t *rapid.T) {
		got = Scenarios(10).Draw(t, "scenario")
	})(t, make([]byte, 1<<12))

	want := Scenario{Start: World{
		Policy: Policy{ACLs: []Rule{{Src: []Sel{{Kind: SelAll}}, Dst: []Dest{{Sel: Sel{Kind: SelAll}}}}}},
		Topology: Topology{
			Users:      []User{{ID: 1, Name: "alice"}},
			Nodes:      []Node{{ID: 1, User: 1, V4: ownAddr(4, 1), V6: ownAddr(6, 1)}},
			NextID:     2,
			NextUserID: 2,
		},
	}}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the simplest draw is\n%#v\nwant\n%#v", got, want)
	}

	if doc := string(got.Start.Policy.HuJSON()); !strings.Contains(doc, `{"action": "accept", "src": ["*"], "dst": ["*:*"]}`) {
		t.Fatalf("the simplest document is\n%s", doc)
	}

	_, nodes := got.Start.Topology.Build()
	if hi := nodes[0].Hostinfo; hi.GoVersion == "" || hi.IPNVersion == "" || !nodes[0].Online() {
		t.Fatalf("the simplest node is not an official, online client: %+v", hi)
	}
}

// policyDoc is a policy document read back as plain JSON.
type policyDoc struct {
	Groups    map[string][]string `json:"groups"`
	TagOwners map[string][]string `json:"tagOwners"`
	Hosts     map[string]string   `json:"hosts"`
	ACLs      *[]struct {
		Action, Proto string
		Src, Dst      []string
	} `json:"acls"`
	Grants *[]struct {
		Src, Dst, IP, Via []string
		App               map[string][]json.RawMessage
	} `json:"grants"`
	SSH       []json.RawMessage `json:"ssh"`
	NodeAttrs []struct {
		Target, Attr []string
	} `json:"nodeAttrs"`
}

// TestHuJSONSaysWhatThePlanSays reads the document back as plain JSON: it
// has the plan's rules, in order, no rule section when it allows
// everything, and defines every name it uses.
func TestHuJSONSaysWhatThePlanSays(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		p := Policies().Draw(t, "policy")

		var doc policyDoc

		err := json.Unmarshal(p.HuJSON(), &doc)
		if err != nil {
			t.Fatalf("not JSON: %v\n%s", err, p.HuJSON())
		}

		if p.AllowAll != (doc.ACLs == nil && doc.Grants == nil) {
			t.Fatalf("allow-all %t, but the document has acls %t, grants %t", p.AllowAll, doc.ACLs != nil, doc.Grants != nil)
		}

		acls, grants := derefDoc(doc.ACLs), derefDoc(doc.Grants)
		if len(acls) != len(p.ACLs) || len(grants) != len(p.Grants) || len(doc.SSH) != len(p.SSH) || len(doc.NodeAttrs) != len(p.NodeAttrs) {
			t.Fatalf("the document has %d acls, %d grants, %d ssh and %d nodeAttrs rules", len(acls), len(grants), len(doc.SSH), len(doc.NodeAttrs))
		}

		names := slices.Concat(docACLs(t, p, acls), docGrants(t, p, grants))
		for _, a := range doc.NodeAttrs {
			names = append(names, a.Target...)
		}

		for _, n := range names {
			var defined bool

			switch {
			case strings.HasPrefix(n, "group:"):
				_, defined = doc.Groups[n]
			case strings.HasPrefix(n, "tag:"):
				_, defined = doc.TagOwners[n]
			case slices.Contains(Hosts, n):
				_, defined = doc.Hosts[n]
			default:
				defined = true
			}

			if !defined {
				t.Fatalf("%s is not defined", n)
			}
		}

		for i := range numTags {
			if _, ok := doc.TagOwners[Tags[i]]; ok != p.DefinesTag(i) {
				t.Fatalf("%s defined %t in the document, %t in the plan", Tags[i], ok, p.DefinesTag(i))
			}
		}
	})
}

func derefDoc[E any](s *[]E) []E {
	if s == nil {
		return nil
	}

	return *s
}

// docACLs holds the document's acls to p's and returns the names they use.
func docACLs(t *rapid.T, p Policy, acls []struct {
	Action, Proto string
	Src, Dst      []string
},
) []string {
	var names []string

	for i, r := range p.ACLs {
		d := acls[i]
		if d.Action != "accept" || d.Proto != Protos[r.Proto] || !slices.Equal(d.Src, selStrings(r.Src)) || len(d.Dst) != len(r.Dst) {
			t.Fatalf("acls[%d] is %+v", i, d)
		}

		for j, dst := range r.Dst {
			if want := dst.Sel.String() + ":" + Ports[dst.Ports]; d.Dst[j] != want {
				t.Fatalf("acls[%d] dst[%d] is %q, want %q", i, j, d.Dst[j], want)
			}

			names = append(names, dst.Sel.String())
		}

		names = append(names, d.Src...)
	}

	return names
}

// docGrants holds the document's grants to p's and returns the names they
// use.
func docGrants(t *rapid.T, p Policy, grants []struct {
	Src, Dst, IP, Via []string
	App               map[string][]json.RawMessage
},
) []string {
	var names []string

	for i, r := range p.Grants {
		d := grants[i]

		ips := make([]string, len(r.IP))
		for j, ip := range r.IP {
			ips[j] = ip.String()
		}

		if !slices.Equal(d.Src, selStrings(r.Src)) || len(d.Dst) != len(r.Dst) || !slices.Equal(d.IP, ips) || len(d.App) != len(r.App) || len(d.Via) != len(r.Via) {
			t.Fatalf("grants[%d] is %+v", i, d)
		}

		for _, a := range r.App {
			if v, ok := d.App[Apps[a.Cap]]; !ok || len(v) != 1 || string(v[0]) != AppValues[a.Value] {
				t.Fatalf("grants[%d] app is %v", i, d.App)
			}
		}

		names = slices.Concat(names, d.Src, d.Dst, d.Via)
	}

	return names
}

// TestEditUndo applies each step and then the step that undoes it. Where
// headscale has an inverse, the plan must come back, but for the ID
// counters; where Undo says there is none, an edit of the step has none
// (a deletion, a replacement onto a token already held), or what stays
// different is approvals, which no write puts back once auto-approval or
// an admin moved them, or the document, which a policy write refuses
// once users made a token in it ambiguous.
func TestEditUndo(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := Scenarios(10).Draw(t, "scenario")

		w := s.Start
		for i, st := range s.Steps {
			next := w.Apply(st.Edits...)

			inv, ok := Undo(w, st)
			back := next.Apply(inv.Edits...)
			back.Topology.NextID, back.Topology.NextUserID = w.Topology.NextID, w.Topology.NextUserID

			// An edit headscale has no inverse for: a deletion, or a
			// replacement onto a token the document held already.
			noInverse, cur := false, w
			for _, e := range st.Edits {
				_, has := e.undo(cur)
				noInverse = noInverse || !has
				cur = cur.Apply(e)
			}

			switch {
			case ok && !reflect.DeepEqual(back, w):
				t.Fatalf("step %d (%s) undone by %s gives\n%#v\nnot\n%#v", i+1, st, inv, back, w)
			case !ok && !noInverse && !onlyApprovalsDiffer(back, w) && len(NewView(back).AmbiguousRefs()) == 0:
				t.Fatalf("step %d (%s): Undo says no write takes it back, yet more than approvals differ after %s:\n%#v\nnot\n%#v", i+1, st, inv, back, w)
			}

			w = next
		}
	})
}

// TestUndoKeepsReplacedTokensApart: a user who makes two tokens ambiguous
// at once, and the write replacing both by one token, has no inverse, as
// replacing back cannot tell which was which; replaced by two tokens it
// does.
func TestUndoKeepsReplacedTokensApart(t *testing.T) {
	t.Parallel()

	alice, bob, carol, dave := 0, 1, 2, 3
	w := World{
		Policy: Policy{
			TagOwners: [numTags][]Sel{2: {{Kind: SelUser, I: alice}}},
			ACLs:      []Rule{{Src: []Sel{{Kind: SelAll}}, Dst: []Dest{{Sel: Sel{Kind: SelUser, I: bob}}}}},
		},
		Topology: Topology{
			Users:      slices.Clone(defaultUsers[:2]),
			Nodes:      []Node{{ID: 1, User: 1, V4: ownAddr(4, 1), V6: ownAddr(6, 1)}},
			NextID:     2,
			NextUserID: 3,
		},
	}
	twin := AddUser{User{ID: 3, Name: "alice", Email: "bob@example.com", Provider: providerPrefix + "3"}}

	if amb := NewView(w.Apply(twin)).AmbiguousRefs(); !slices.Equal(amb, []int{alice, bob}) {
		t.Fatalf("the new user makes %v ambiguous", amb)
	}

	for _, tc := range []struct {
		to      []int
		inverse bool
	}{
		{[]int{carol, carol}, false},
		{[]int{carol, dave}, true},
	} {
		replace := ReplaceUserRefs{From: []int{alice, bob}, To: tc.to}
		step := Step{Edits: []Edit{twin, replace}}

		// Undo alone would say false either way: it also compares the
		// world it gets back. The edit must know it has no inverse.
		if back, has := replace.undo(w.Apply(twin)); has != tc.inverse {
			t.Fatalf("%s: the edit says it has an inverse %t (%v)", replace, has, back)
		}

		inv, ok := Undo(w, step)
		back := w.Apply(step.Edits...).Apply(inv.Edits...)
		back.Topology.NextID, back.Topology.NextUserID = w.Topology.NextID, w.Topology.NextUserID

		if ok != tc.inverse || ok && !reflect.DeepEqual(back, w) {
			t.Fatalf("%s: Undo says %t, undone by %s gives\n%#v", step, ok, inv, back)
		}
	}
}

// onlyApprovalsDiffer reports whether a and b differ in nodes' approvals
// alone.
func onlyApprovalsDiffer(a, b World) bool {
	strip := func(w World) World {
		c := w.clone()
		for i := range c.Topology.Nodes {
			c.Topology.Nodes[i].Approved, c.Topology.Nodes[i].AutoApproved = nil, nil
		}

		return c
	}

	return reflect.DeepEqual(strip(a), strip(b))
}

// TestEditsChangeWhatTheySay applies each edit alone and holds what moved
// to its name, and to what headscale changes with it: auto-approval when
// routes, tags or a registration change. A property can then tell which
// input a failure needed.
func TestEditsChangeWhatTheySay(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := Scenarios(10).Draw(t, "scenario")

		w := s.Start
		for _, st := range s.Steps {
			for _, e := range st.Edits {
				next := w.Apply(e)

				got, want := touched(w, next), mayTouch(w, e)
				for _, g := range got {
					if !slices.Contains(want, g) {
						t.Fatalf("%s changed %s; it may change only %v", e, g, want)
					}
				}

				w = next
			}
		}
	})
}

// TestWorldsAreReachable holds every world a scenario passes through, and
// every write it makes, to what headscale's own writes allow: a tagged
// node has no user and was tagged with tags the policy defined; an
// untagged node's user exists; API users' names are unique among them,
// provider identifiers unique; no ID is handed out twice; a registered
// node has nothing approved but what auto-approval approved; an
// auto-approval is of a route still announced; a policy write holds no
// token two users answer to, nor does the start.
func TestWorldsAreReachable(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := Scenarios(10).Draw(t, "scenario")

		err := checkReachable(s.Start)
		if err == nil && len(NewView(s.Start).AmbiguousRefs()) > 0 {
			err = fmt.Errorf("%w: the start's policy holds an ambiguous token", errUnreachable)
		}

		if err != nil {
			t.Fatalf("the start: %v", err)
		}

		w := s.Start
		for i, st := range s.Steps {
			cur := w

			for _, e := range st.Edits {
				err := checkWrite(cur, e)
				if err != nil {
					t.Fatalf("step %d (%s): %s: %v", i+1, st, e, err)
				}

				cur = cur.Apply(e)
			}

			if err := checkReachable(cur); err != nil { //nolint:noinlineerr
				t.Fatalf("after step %d (%s): %v", i+1, st, err)
			}

			for _, id := range st.Reads {
				if _, ok := cur.Topology.Node(id); !ok {
					t.Fatalf("step %d: n%d reads, but is not there", i+1, id)
				}
			}

			w = cur
		}
	})
}

var errUnreachable = errors.New("not something headscale's writes produce")

func checkReachable(w World) error {
	tp := w.Topology

	if !slices.IsSortedFunc(tp.Users, func(a, b User) int { return cmp.Compare(a.ID, b.ID) }) {
		return fmt.Errorf("%w: users out of order: %v", errUnreachable, tp.Users)
	}

	for i, u := range tp.Users {
		if u.ID >= tp.NextUserID {
			return fmt.Errorf("%w: u%d at or past the next user ID %d", errUnreachable, u.ID, tp.NextUserID)
		}

		for _, o := range tp.Users[i+1:] {
			if !u.OIDC() && !o.OIDC() && u.Name == o.Name || u.OIDC() && u.Provider == o.Provider {
				return fmt.Errorf("%w: u%d and u%d collide: %v %v", errUnreachable, u.ID, o.ID, u, o)
			}
		}
	}

	for i, n := range tp.Nodes {
		if i > 0 && tp.Nodes[i-1].ID >= n.ID {
			return fmt.Errorf("%w: nodes out of order at n%d", errUnreachable, n.ID)
		}

		if n.ID >= tp.NextID {
			return fmt.Errorf("%w: n%d at or past the next ID %d", errUnreachable, n.ID, tp.NextID)
		}

		_, ok := tp.User(n.User)

		switch {
		case n.Tagged() && n.User != 0:
			return fmt.Errorf("%w: tagged n%d has user u%d", errUnreachable, n.ID, n.User)
		case !n.Tagged() && !ok:
			return fmt.Errorf("%w: n%d belongs to u%d, who does not exist", errUnreachable, n.ID, n.User)
		}

		for _, rs := range [][]int{n.Tags, n.Announced, n.Approved, n.AutoApproved} {
			if !slices.IsSorted(rs) || len(slices.Compact(slices.Clone(rs))) != len(rs) {
				return fmt.Errorf("%w: n%d has an unsorted list %v", errUnreachable, n.ID, rs)
			}
		}

		if len(dropRoutes(n.AutoApproved, keepRoutes(n.Approved, n.Announced))) > 0 {
			return fmt.Errorf("%w: n%d keeps an auto-approval of a route it does not announce and serve: %v", errUnreachable, n.ID, n)
		}
	}

	return nil
}

// checkWrite holds e, written to w, to what headscale accepts.
func checkWrite(w World, e Edit) error {
	next := w.Apply(e)

	defined := func(tags []int) bool {
		return !slices.ContainsFunc(tags, func(t int) bool { return !w.Policy.DefinesTag(t) })
	}

	switch e := e.(type) {
	case Join:
		switch {
		case e.Node.ID < w.Topology.nextID():
			return fmt.Errorf("%w: registered under an ID handed out before", errUnreachable)
		case !defined(e.Node.Tags):
			return fmt.Errorf("%w: registered with tags the policy does not define", errUnreachable)
		case len(e.Node.Approved) > 0 || e.Node.Expired:
			return fmt.Errorf("%w: registered with approvals or expired", errUnreachable)
		case !e.Node.Tagged() && func() bool { _, ok := w.Topology.User(e.Node.User); return !ok }():
			return fmt.Errorf("%w: registered for a user who does not exist", errUnreachable)
		}
	case Retag:
		if len(e.Tags) > 0 && !defined(e.Tags) {
			return fmt.Errorf("%w: tagged with tags the policy does not define", errUnreachable)
		}
	case AddUser:
		if e.User.ID < w.Topology.nextUserID() {
			return fmt.Errorf("%w: created under an ID handed out before", errUnreachable)
		}
	case DeleteUser:
		if slices.ContainsFunc(w.Topology.Nodes, func(n Node) bool { return n.User == e.ID }) {
			return fmt.Errorf("%w: deleted a user who owns a node", errUnreachable)
		}
	case SetEmail:
		if u, _ := w.Topology.User(e.ID); !u.OIDC() {
			return fmt.Errorf("%w: an API user's e-mail changed", errUnreachable)
		}
	}

	if !reflect.DeepEqual(w.Policy, next.Policy) && len(NewView(next).AmbiguousRefs()) > 0 {
		return fmt.Errorf("%w: a policy write holding a token several users answer to", errUnreachable)
	}

	return nil
}

// TestCommitTellsWhatChanged replays each step's Change on a mirror of
// the nodes: deleting what it removes and writing what it names must give
// the next world's nodes, a node whose user changed must be written, and
// the users and policy flags must be exact.
func TestCommitTellsWhatChanged(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		s := Scenarios(10).Draw(t, "scenario")

		mirror := map[types.NodeID]Node{}
		for _, n := range s.Start.Topology.Nodes {
			mirror[n.ID] = n
		}

		w := s.Start
		for i, st := range s.Steps {
			next, c := w.Commit(st)

			for _, id := range c.Removed {
				delete(mirror, id)
			}

			for _, id := range c.Nodes {
				mirror[id], _ = next.Topology.Node(id)
			}

			if got := slices.SortedFunc(maps.Values(mirror), func(a, b Node) int { return cmp.Compare(a.ID, b.ID) }); !reflect.DeepEqual(got, next.Topology.Nodes) {
				t.Fatalf("step %d (%s): %+v leaves the nodes\n%v\nnot\n%v", i+1, st, c, got, next.Topology.Nodes)
			}

			for _, n := range next.Topology.Nodes {
				u0, _ := w.Topology.User(n.User)
				u1, _ := next.Topology.User(n.User)

				if u0 != u1 && !slices.Contains(c.Nodes, n.ID) {
					t.Fatalf("step %d (%s): n%d's user changed, and it is not written: %+v", i+1, st, n.ID, c)
				}
			}

			if c.Users != !slices.Equal(w.Topology.Users, next.Topology.Users) || c.Policy != (string(w.Policy.HuJSON()) != string(next.Policy.HuJSON())) {
				t.Fatalf("step %d (%s): %+v", i+1, st, c)
			}

			w = next
		}
	})
}

// touched lists what differs from before to after: "users", and per node
// and per part of the policy what changed.
func touched(before, after World) []string {
	var out []string

	if !reflect.DeepEqual(before.Topology.Users, after.Topology.Users) {
		out = append(out, "users")
	}

	ids := map[types.NodeID]bool{}
	for _, n := range slices.Concat(before.Topology.Nodes, after.Topology.Nodes) {
		ids[n.ID] = true
	}

	for _, id := range slices.Sorted(maps.Keys(ids)) {
		b, okb := before.Topology.Node(id)
		a, oka := after.Topology.Node(id)

		switch {
		case !okb:
			out = append(out, fmt.Sprintf("n%d joined", id))
		case !oka:
			out = append(out, fmt.Sprintf("n%d left", id))
		default:
			bv, av := reflect.ValueOf(b), reflect.ValueOf(a)
			for i := range bv.NumField() {
				if !reflect.DeepEqual(bv.Field(i).Interface(), av.Field(i).Interface()) {
					out = append(out, fmt.Sprintf("n%d %s", id, bv.Type().Field(i).Name))
				}
			}
		}
	}

	bp, ap := before.Policy, after.Policy
	for i := range numGroups {
		if !slices.Equal(bp.Groups[i], ap.Groups[i]) {
			out = append(out, Groups[i])
		}
	}

	for i := range numTags {
		if !slices.Equal(bp.TagOwners[i], ap.TagOwners[i]) || bp.Defined[i] != ap.Defined[i] {
			out = append(out, "tagOwners "+Tags[i])
		}
	}

	for i := range numHosts {
		if bp.Hosts[i] != ap.Hosts[i] {
			out = append(out, Hosts[i])
		}
	}

	if bp.AllowAll != ap.AllowAll {
		out = append(out, "allow-all")
	}

	for _, grant := range []bool{false, true} {
		bl, al := bp.List(grant), ap.List(grant)
		if len(bl) != len(al) {
			out = append(out, listName(grant)+" list")

			continue
		}

		for i := range bl {
			if !reflect.DeepEqual(bl[i], al[i]) {
				out = append(out, RuleRef{grant, i}.String())
			}
		}
	}

	for _, part := range []struct {
		name    string
		changed bool
	}{
		{"ssh", !reflect.DeepEqual(bp.SSH, ap.SSH)},
		{"nodeAttrs", !reflect.DeepEqual(bp.NodeAttrs, ap.NodeAttrs)},
		{"autoApprovers", !reflect.DeepEqual(bp.AutoApprovers, ap.AutoApprovers)},
	} {
		if part.changed {
			out = append(out, part.name)
		}
	}

	return out
}

// nodeTouch is mayTouch for an edit of one node, nil for any other.
func nodeTouch(e Edit) []string {
	node := func(id types.NodeID, fields ...string) []string {
		out := make([]string, len(fields))
		for i, f := range fields {
			out[i] = fmt.Sprintf("n%d %s", id, f)
		}

		return out
	}

	family := func(f int) string { return "V" + strconv.Itoa(f) }

	switch e := e.(type) {
	case Join:
		return node(e.Node.ID, "joined")
	case Leave:
		return node(e.ID, "left")
	case Retag:
		return node(e.ID, "Tags", "User", "Approved", "AutoApproved")
	case SetAddr:
		return node(e.ID, family(e.Family))
	case SwapAddrs:
		return slices.Concat(node(e.A, family(e.Family)), node(e.B, family(e.Family)))
	case Announce:
		return node(e.ID, "Announced", "Approved", "AutoApproved")
	case Withdraw:
		return node(e.ID, "Announced", "Approved", "AutoApproved")
	case Approve:
		return node(e.ID, "Approved", "AutoApproved")
	case Unapprove:
		return node(e.ID, "Approved", "AutoApproved")
	case SetClient:
		return node(e.ID, "Client")
	case SetExpired:
		return node(e.ID, "Expired")
	case SetOnline:
		return node(e.ID, "Offline")
	}

	return nil
}

// mayTouch is what e's name says it changes, and what headscale changes
// with it, as touched writes it.
func mayTouch(w World, e Edit) []string {
	if out := nodeTouch(e); out != nil {
		return out
	}

	whole := []string{"acls list", "grants list", "allow-all"}

	switch e := e.(type) {
	case AddUser, DeleteUser, RenameUser, SetEmail:
		return []string{"users"}
	case SetPorts:
		return []string{e.Rule.String()}
	case SetProto:
		return []string{e.Rule.String()}
	case SetIP:
		return []string{e.Rule.String()}
	case SetApp:
		return []string{e.Rule.String()}
	case SetVia:
		return []string{e.Rule.String()}
	case SetSel:
		return []string{e.Rule.String()}
	case AddSel:
		return []string{e.Rule.String()}
	case RemoveSel:
		return []string{e.Rule.String()}
	case SwapRules:
		return []string{RuleRef{e.Grant, e.I}.String(), RuleRef{e.Grant, e.J}.String()}
	case SetGroup:
		return []string{Groups[e.Group]}
	case SetHost:
		return []string{Hosts[e.Host]}
	case SetTagOwners:
		return []string{"tagOwners " + Tags[e.Tag]}
	case AddRule:
		return []string{listName(e.Ref.Grant) + " list", "allow-all"}
	case RemoveRule:
		return []string{listName(e.Ref.Grant) + " list"}
	case AllowAll, SetRules:
		return whole
	case ReplaceUserRefs:
		return everyPart(w)
	case SetSSH:
		return []string{"ssh"}
	case SetNodeAttrs:
		return []string{"nodeAttrs"}
	case SetAutoApprovers:
		return []string{"autoApprovers"}
	}

	panic(fmt.Sprintf("no rule for %T", e))
}

// everyPart is every part of w's policy a token can be in.
func everyPart(w World) []string {
	out := slices.Concat(Groups, []string{"ssh", "nodeAttrs", "autoApprovers"})

	for _, t := range Tags {
		out = append(out, "tagOwners "+t)
	}

	for _, ref := range w.Policy.Refs() {
		out = append(out, ref.String())
	}

	return out
}

func listName(grant bool) string {
	if grant {
		return "grants"
	}

	return "acls"
}

// TestShrinksToSmallCases runs properties that fail on purpose and
// requires rapid to minimise each to a case a person can read, with
// nothing in it the failure does not need. The last is what a builder's
// failing property prints. RAPID_SEED picks another seed.
func TestShrinksToSmallCases(t *testing.T) {
	// The race detector slows the shrinker past its time budget, which
	// leaves cases half shrunk; shrinking runs on one goroutine and gains
	// nothing from it.
	if util.RaceEnabled {
		t.Skip("shrinking runs out of its time budget under the race detector")
	}

	// Fail files go nowhere, and the seed is fixed, whatever seed the
	// properties are given: shrinking reaches the smallest case from some
	// seeds, not all. Database-only shapes are rare, so a property may
	// need more than the default checks to fail. Flags are process-wide:
	// not parallel.
	settings := map[string]string{"rapid.nofailfile": "true", "rapid.seed": "3", "rapid.checks": "1000"}

	for name, value := range settings {
		old := flag.Lookup(name).Value.String()

		err := flag.Set(name, value)
		if err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = flag.Set(name, old) })
	}

	worldCase := func(name string, fails func(*View) string, needs ...string) {
		t.Run(name, func(t *testing.T) {
			var last World

			out := failing(t, func(t *rapid.T) {
				w := Worlds().Draw(t, "world")
				last = w

				if why := fails(NewView(w)); why != "" {
					t.Fatal(why)
				}
			})

			if left := leftovers(Scenario{Start: last}, needs); len(left) > 0 {
				t.Errorf("minimised with leftovers %v:\n%s", left, out)
			}
		})
	}

	worldCase("a shared address", func(v *View) string {
		if v.sharedAddr() {
			return "two nodes share an address"
		}

		return ""
	}, "node", "shared", "shared")

	worldCase("a served route covering a node", func(v *View) string {
		for _, r := range v.nodes {
			for _, rt := range served(r) {
				if rt < numRulePrefixes && v.anyNode(func(n Node) bool { return n.ID != r.ID && slices.ContainsFunc(n.Addrs(), Prefixes[rt].Contains) }) {
					return fmt.Sprintf("n%d serves %s, which holds another node's address", r.ID, Prefixes[rt])
				}
			}
		}

		return ""
	}, "node", "route")

	t.Run("a policy edit moving a rule's source", func(t *testing.T) {
		var last Scenario

		out := failing(t, func(t *rapid.T) {
			s := Scenarios(10).Draw(t, "scenario")
			last = s

			w := s.Start
			for i, st := range s.Steps {
				next := w.Apply(st.Edits...)
				for _, e := range edits[SetSel](st) {
					if !e.Dst && ruleChanged(NewView(w), NewView(next), e.Rule) {
						t.Fatalf("step %d moves %s's source", i+1, e.Rule)
					}
				}

				w = next
			}
		})

		// A move needs a selector other than *, before it or after: in
		// the start, or added by a step of its own.
		left := leftovers(last, []string{"step", "edit", "policy"})
		added := len(last.Steps) > 0 && len(edits[AddRule](last.Steps[0]))+len(edits[SetSel](last.Steps[0])) > 0

		if len(left) > 0 && (!added || len(leftovers(last, []string{"step", "step", "edit", "edit"})) > 0) {
			t.Errorf("minimised with leftovers %v:\n%s", left, out)
		}
	})

	t.Run("a system that loses retags after a node goes offline", func(t *testing.T) {
		var last Scenario

		out := failing(t, func(t *rapid.T) {
			s := Scenarios(10).Draw(t, "scenario")
			last = s

			sys := newToySystem(s.Start)
			w := s.Start

			for i, st := range s.Steps {
				next, change := w.Commit(st)
				sys.commit(change, next)

				for _, n := range next.Topology.Nodes {
					if !slices.Equal(sys.tags[n.ID], n.Tags) {
						t.Fatalf("after step %d n%d has tags %v, want %v", i+1, n.ID, tagNames(sys.tags[n.ID]), tagNames(n.Tags))
					}
				}

				w = next
			}
		})

		edits := 0
		for _, st := range last.Steps {
			edits += len(st.Edits)
		}

		if len(last.Start.Topology.Nodes) > 2 || edits > 2 {
			t.Errorf("minimised to %d nodes and %d edits:\n%s", len(last.Start.Topology.Nodes), edits, out)
		}
	})
}

// leftovers lists what s holds beyond the plain case: one user, one node
// on its own addresses, the single allow rule, no step; less what needs,
// a multiset of the same words, says the failure needs.
func leftovers(s Scenario, needs []string) []string {
	var got []string

	w := s.Start
	plain := Policy{ACLs: []Rule{{Src: []Sel{{Kind: SelAll}}, Dst: []Dest{{Sel: Sel{Kind: SelAll}}}}}}

	if !reflect.DeepEqual(canonPolicy(w.Policy), plain) {
		got = append(got, "policy")
	}

	for range max(0, len(w.Topology.Users)-1) {
		got = append(got, "user")
	}

	for _, u := range w.Topology.Users {
		if int(u.ID) > len(defaultUsers) || u != defaultUsers[u.ID-1] {
			got = append(got, "user identity")
		}
	}

	for range max(0, len(w.Topology.Nodes)-1) {
		got = append(got, "node")
	}

	v := NewView(w)

	for _, n := range w.Topology.Nodes {
		plainNode := Node{ID: n.ID, User: n.User, V4: ownAddr(4, uint64(n.ID)), V6: ownAddr(6, uint64(n.ID))}

		switch {
		case slices.ContainsFunc(n.Addrs(), Outside):
			got = append(got, "outside")
		case slices.ContainsFunc(n.Addrs(), func(a netip.Addr) bool { return v.heldByOther(n, a) }):
			got = append(got, "shared")
		case len(n.Addrs()) == 1:
			got = append(got, "single-family")
		case n.V4 != plainNode.V4 || n.V6 != plainNode.V6:
			got = append(got, "address")
		}

		if n.Tagged() {
			got = append(got, "tag")
		}

		if len(n.Announced) > 0 || len(n.Approved) > 0 {
			got = append(got, "route")
		}

		if n.Client != Official || n.Expired || n.Offline {
			got = append(got, "client state")
		}
	}

	for _, st := range s.Steps {
		got = append(got, "step")

		for range st.Edits {
			got = append(got, "edit")
		}

		if len(st.Reads) > 0 {
			got = append(got, "read")
		}
	}

	for _, n := range needs {
		if i := slices.Index(got, n); i >= 0 {
			got = slices.Delete(got, i, i+1)
		}
	}

	return got
}

func tagNames(tags []int) []string {
	out := make([]string, len(tags))
	for i, t := range tags {
		out[i] = Tags[t]
	}

	return out
}

// toySystem follows a world's node tags from what [World.Commit] reports,
// and stops following a node's tags once it has gone offline: the bug the
// property above finds.
type toySystem struct {
	tags map[types.NodeID][]int
	lost map[types.NodeID]bool
}

func newToySystem(w World) *toySystem {
	s := &toySystem{tags: map[types.NodeID][]int{}, lost: map[types.NodeID]bool{}}
	for _, n := range w.Topology.Nodes {
		s.tags[n.ID], s.lost[n.ID] = n.Tags, n.Offline
	}

	return s
}

func (s *toySystem) commit(c Change, w World) {
	for _, id := range c.Removed {
		delete(s.tags, id)
	}

	for _, id := range c.Nodes {
		n, _ := w.Topology.Node(id)
		s.lost[id] = s.lost[id] || n.Offline

		if !s.lost[id] {
			s.tags[id] = n.Tags
		}
	}
}

// failing runs prop under rapid, which must find it failing, and returns
// what rapid printed.
func failing(t *testing.T, prop func(*rapid.T)) string {
	t.Helper()

	fl := &failureLog{name: t.Name()}
	rapid.Check(fl, prop)

	if !fl.failed {
		t.Fatal("the property did not fail")
	}

	out := strings.Join(fl.lines, "\n")
	t.Log(out)

	return out
}

// failureLog is a [rapid.TB] that keeps what rapid reports instead of
// failing the test.
type failureLog struct {
	name   string
	lines  []string
	failed bool
}

func (r *failureLog) Helper()      {}
func (r *failureLog) Name() string { return r.name }
func (r *failureLog) Logf(format string, args ...any) {
	r.lines = append(r.lines, fmt.Sprintf(format, args...))
}
func (r *failureLog) Log(args ...any) { r.lines = append(r.lines, fmt.Sprint(args...)) }
func (r *failureLog) Skipf(format string, args ...any) {
	r.Logf(format, args...)
}
func (r *failureLog) Skip(args ...any) { r.Log(args...) }
func (r *failureLog) SkipNow()         {}
func (r *failureLog) Errorf(format string, args ...any) {
	r.failed = true
	r.Logf(format, args...)
}

func (r *failureLog) Error(args ...any) {
	r.failed = true
	r.Log(args...)
}
func (r *failureLog) Fatalf(format string, args ...any) { r.Errorf(format, args...) }
func (r *failureLog) Fatal(args ...any)                 { r.Error(args...) }
func (r *failureLog) FailNow()                          { r.failed = true }
func (r *failureLog) Fail()                             { r.failed = true }
func (r *failureLog) Failed() bool                      { return r.failed }
