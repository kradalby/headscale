package state

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"reflect"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/graph"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/policy/matcher"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog/log"
	"tailscale.com/envknob"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"tailscale.com/util/dnsname"
)

// fallbackGivenName is the DNS label used when a node is written with
// an empty [types.Node.GivenName]. Matches Tailscale SaaS behaviour
// for empty sanitised labels.
const fallbackGivenName = "node"

// Errors returned by [world.SetGivenName].
var (
	ErrGivenNameTaken   = errors.New("given name already in use by another node")
	ErrGivenNameInvalid = errors.New("given name is not a valid DNS label")
)

const prometheusNamespace = "headscale"

// worldCommitPanics counts node write commits that panicked.
var worldCommitPanics atomic.Uint64

var (
	worldCommits = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "world_commits_total",
		Help:      "Control-plane graph transactions publishing a new snapshot after the initial snapshot, including node, user, policy, DNS and DERP changes. Transactions that stage no edit — an unknown node, unchanged users, a byte-identical policy, equal DNS records or DERP maps — and refused and panicking ones are excluded; a panicking node batch is retried write by write, each surviving publication counting separately. A node write that stages an identical copy of the node still counts, as does a commit whose policy recompile fails. This does not count database persistence or client delivery.",
	})
	_ = promauto.NewCounterFunc(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "world_commit_panics_total",
		Help:      "Node write commits that panicked; a batch's writers are retried individually, so only the writers that panic again fail. The graph kept serving.",
	}, func() float64 { return float64(worldCommitPanics.Load()) })
	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "policy_capability_sources_enabled",
		Help:      "1 when the latest server names filter sources by node capability (policy.capability_sources).",
	}, func() float64 {
		if w := censusWorld.Load(); w != nil && w.capSources {
			return 1
		}

		return 0
	})
	worldNodes = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: prometheusNamespace,
		Name:      "world_nodes",
		Help:      "Nodes in the control-plane graph.",
	})
	worldBatchSize = promauto.NewHistogram(prometheus.HistogramOpts{
		Namespace: prometheusNamespace,
		Name:      "world_write_batch_size",
		Help:      "Node writes in completed batches, including no-op batches. Panicking batches are excluded; successful individual retries are observed separately.",
		Buckets:   []float64{1, 2, 5, 10, 20, 50, 100, 200},
	})
	policyCompiles = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: prometheusNamespace,
		Name:      "policy_compiles_total",
		Help:      "Policy compilations in the graph by result: at boot and on each change to the document, the users, or a node field the policy reads, published or refused; one write compiles up to three times when users or nodes move during its tests. A document refused before it reaches the graph, a write's own test candidate and the audit's compile are not counted.",
	}, []string{"result"})

	// policyAudit compiles every policy from scratch as well and reports
	// where the incremental compile differs.
	policyAudit         = envknob.RegisterBool("HEADSCALE_DEBUG_POLICY_AUDIT")
	policyAuditFailures atomic.Uint64
	policyAuditRuns     atomic.Uint64
	membershipAuditRuns atomic.Uint64
	filterAuditRuns     atomic.Uint64
	servedAuditRuns     atomic.Uint64
	sidesAuditRuns      atomic.Uint64
	viaPlanAuditRuns    atomic.Uint64
)

// SidesAuditRuns counts the audits of role-based visibility, route access
// and via steering that ran, and ViaPlanAuditRuns those of the elections
// against the via plan, so a test can prove they are wired; their failures
// count in [PolicyAuditFailures].
func SidesAuditRuns() uint64 { return sidesAuditRuns.Load() }

// ViaPlanAuditRuns: see [SidesAuditRuns].
func ViaPlanAuditRuns() uint64 { return viaPlanAuditRuns.Load() }

// PolicyAudit reports whether HEADSCALE_DEBUG_POLICY_AUDIT is on: what
// is served, and whom routing tells, are then held against an oracle.
func PolicyAudit() bool { return policyAudit() }

// FilterCuts counts the node filters the served filters have cut, so a
// benchmark can tell how many renders recut an unchanged filter.
func FilterCuts() uint64 { return policyv2.FilterCuts() }

// ExpansionBuilds counts the expansions the served filters have built.
func ExpansionBuilds() uint64 { return policyv2.ExpansionBuilds() }

// FilterAuditRuns counts the filter audits that ran, and ServedAuditRuns
// the served filters held to a fresh cut when read, so a test can prove
// the audits are wired; their failures count in [PolicyAuditFailures].
func FilterAuditRuns() uint64 { return filterAuditRuns.Load() }

// ServedAuditRuns: see [FilterAuditRuns].
func ServedAuditRuns() uint64 { return servedAuditRuns.Load() }

// MembershipAuditRuns counts the membership audits that ran, so a test
// can prove the audit is wired; their failures count in
// [PolicyAuditFailures].
func MembershipAuditRuns() uint64 { return membershipAuditRuns.Load() }

// PolicyAuditFailures counts the compiles the policy audit found to
// differ from a compile from scratch.
func PolicyAuditFailures() uint64 { return policyAuditFailures.Load() }

// PolicyAuditRuns counts the from-scratch via election audits that ran,
// so a test can prove the audit is wired, not merely quiet.
func PolicyAuditRuns() uint64 { return policyAuditRuns.Load() }

// nodeMap is the set of nodes. A stored node is never mutated: a write
// stores a modified copy, so a [types.NodeView] taken from a snapshot stays
// valid and two snapshots holding the same pointer hold the same node.
type nodeMap = graph.Map[types.NodeID, *types.Node]

// nodeEdit stages a write to the nodes. It tracks the given names the
// write sets, so a name is checked against the committed name index and
// the batch's own writes instead of every node.
type nodeEdit struct {
	*graph.MapEdit[types.NodeID, *types.Node]

	// names indexes the nodes the edit started from.
	names graph.Grouped[types.NodeID, *types.Node, string]
	// staged holds, per folded name, the nodes this edit gave it.
	staged map[string][]types.NodeID
	// users is the committed users list.
	users []types.User
	dns   types.DNSView
}

// Set stages id = n. A user copy n brings that differs from the stored
// node's is replaced by the users list's: [world.SetUsers] refreshes only
// the nodes of users that change, so a copy read before a user change and
// written after it would otherwise stay until that user next changes.
func (e *nodeEdit) Set(id types.NodeID, n *types.Node) {
	old, had := e.Get(id)

	if n.UserID != nil && n.User != nil &&
		(!had || old.User == nil || !sameUserForNodes(*old.User, *n.User)) {
		e.currentUser(n)
	}

	e.MapEdit.Set(id, n)

	// A kept name is already indexed, committed or staged.
	if had && old.GivenName == n.GivenName {
		return
	}

	folded := strings.ToLower(n.GivenName)

	if e.staged == nil {
		e.staged = map[string][]types.NodeID{}
	}

	e.staged[folded] = append(e.staged[folded], id)
}

// currentUser points n at the users list's copy of its user, when the list
// has it: a user created by the write's own registration is not listed
// until the refresh that follows.
func (e *nodeEdit) currentUser(n *types.Node) {
	for i := range e.users {
		if u := e.users[i]; u.ID == *n.UserID {
			if !sameUserForNodes(u, *n.User) {
				n.User = &u
			}

			return
		}
	}
}

// nameTaken reports whether a node other than self holds name,
// case-insensitively, with the staged writes applied.
func (e *nodeEdit) nameTaken(self types.NodeID, name string) bool {
	if reservedLabel(e.dns, name) {
		return true
	}

	folded := strings.ToLower(name)
	committed, _ := e.names.Groups.Get(folded)

	for _, ids := range [][]types.NodeID{committed, e.staged[folded]} {
		for _, id := range ids {
			// A holder may since have been renamed or deleted.
			if n, ok := e.Get(id); ok && id != self && strings.ToLower(n.GivenName) == folded {
				return true
			}
		}
	}

	return false
}

// world is the control plane as a dataflow graph. Its inputs are what the
// server is told: nodes, users, the policy document, the DERP map and the
// extra DNS records. Everything else is derived and recomputed only when
// what it read changed:
//
//	nodes ──► index ──► policyNodes ─┬─► policy
//	users ───────────────────────────┤
//	policySrc ───────────────────────┘
//	policy ──► selectors ──► userSets ◄── users
//	userSets, nodes ──► roles ──► postings
//	selectors ──► templates
//	nodes ──► approvals
//	templates, roles, postings, approvals, nodes ──► sides ──► peers, viaPlan
//	templates, postings, approvals, policyNodes, sides ──► filters
//	index, nodes, viaPlan, sides ──► primaries
//	sides, viaPlan ──► routeRules
//
// What clients are sent of the policy — packet filters, peers, the routes
// a viewer may use, via steering and elections — comes from the cells
// after policy, which read the document and membership, never the compiled
// policy's address sets, and so does whom [Snapshot.Since] tells a change
// reaches. The compile still serves SSH, node attributes, tag owners,
// auto-approvers and DERP, and says which document is in force; under the
// policy audit it is the oracle the served values are held against.
//
// The nodes, users and policySrc inputs are written only through the
// methods below, which serialise on the graph.
type world struct {
	g *graph.Graph

	// writeMu guards the group-commit queue of node writes.
	writeMu    sync.Mutex
	writes     []*nodeWrite
	committing bool

	// batchSize and batchTimeout are [types.Tuning.NodeStoreBatchSize] and
	// [types.Tuning.NodeStoreBatchTimeout]: during an HA outage a commit
	// waits up to the timeout for writes to batch, or until batchSize are
	// queued. Zero waits for nothing. full wakes a waiting commit once the
	// batch is full. inOutage is refreshed when batching is enabled and
	// election inputs change, see [hasOutage].
	batchSize    int
	batchTimeout time.Duration
	full         chan struct{}
	inOutage     atomic.Bool

	// servesRoute is [types.Config.ServesRoute]; nil serves every route.
	servesRoute func(netip.Prefix) bool

	// outageMu and outageRev order the outage stores: a state computed
	// from an older snapshot than the one already stored must not win,
	// whichever of two concurrent writers finished first.
	outageMu  sync.Mutex
	outageRev uint64

	// outageStores and routesClones are test oracles, world-owned so a
	// test reads exact deltas from its own synchronous writes and no
	// other test's world can interfere.
	outageStores atomic.Uint64
	routesClones atomic.Uint64

	// beforePolicyCommit, for tests, runs just before [world.SetPolicy]
	// takes the graph's lock: the last point a write can land between a
	// caller's checks and the commit.
	beforePolicyCommit func()

	nodes         graph.Input[*nodeMap]
	users         graph.Input[[]types.User]
	policyUsers   graph.Derived[[]types.User]
	policySrc     graph.Input[[]byte]
	derpMap       graph.Input[*tailcfg.DERPMap]
	effectiveDERP graph.Derived[*tailcfg.DERPMap]
	dns           graph.Input[types.DNSView]

	index       graph.Derived[*nodeIndex]
	policyNodes graph.Derived[policyNodes]
	policy      graph.Derived[*compiledPolicy]
	// nodeCaps is the policy's capability map per node, kept as a Map so
	// a reader finds whose caps a recompile changed.
	nodeCaps graph.Derived[*capsMap]

	// capSources is policy.capability_sources, fixed for the world's life.
	// With it, receivers holds what decides each node's filter form beyond
	// the policy, stamps the source capabilities each node holds, and
	// renderCaps each node's capabilities as peers and itself are sent
	// them: the policy's and its stamps. Without, none is registered and
	// nodes are rendered with the policy's capabilities.
	capSources bool
	// filterChunks is policy.filter_chunks, fixed for the world's life: the
	// mapper sends filters as named chunks where the client allows
	// ([policyv2.FilterDelivery]). It moves no cell.
	filterChunks bool
	receivers    graph.Derived[policyv2.Receivers]
	stamps       graph.Derived[stampsMap]
	renderCaps   graph.Derived[renderCaps]
	// holders is, in capability mode, the nodes holding each address,
	// which a session reads to tell when a client's address index needs a
	// whole peer list.
	holders graph.Derived[addressHolders]

	// Membership: the selectors the policy in force names; the users each
	// user selector names; each node's role set; and each role's nodes.
	// Each recomputes only for what its inputs changed, so a user outside
	// every selector, an endpoint or a Hostinfo write reaches no role, and
	// a join reaches one node's.
	selectors graph.Derived[*policyv2.Selectors]
	userSets  graph.Derived[*policyv2.UserSets]
	roles     graph.Derived[policyv2.Roles]
	postings  graph.Derived[policyv2.Postings]

	// The policy's rules as templates naming selectors, which only a
	// document edit reaches; and the approved subnet routes a * source
	// adds, which only an approval reaches.
	templates graph.Derived[*policyv2.Templates]
	approvals graph.Derived[policyv2.SubnetApprovals]

	// filters serves every node's packet filter, expanded from the
	// templates and postings when a session first reads it.
	filters graph.Derived[*policyv2.Filters]

	// Who sees whom, which routes a viewer may use and via steering, from
	// the templates and roles: each node's side set, the peer classes
	// keyed by it, and the via elections' scopes, kept by identity while
	// their content stays.
	sides     graph.Derived[policyv2.Sides]
	peers     graph.Derived[*policyv2.PeerClasses]
	viaPlan   graph.Derived[policyv2.ViaPlans]
	primaries graph.Derived[primaryRoutes]
	// routeRules is what routes read beyond viewers, peers and the cover
	// of the peers' routes, for change routing.
	routeRules graph.Derived[policyv2.RouteRules]

	// membershipAudit, filterAudit and sidesAudit are the audits, set,
	// with auditing, only under the policy audit.
	membershipAudit graph.Derived[membershipAudit]
	filterAudit     graph.Derived[filterAudit]
	sidesAudit      graph.Derived[sidesAudit]
	auditing        bool
}

// nodeIndex holds the lookups every reader needs. Each part moves only
// the nodes a commit changed.
type nodeIndex struct {
	from         *nodeMap     // the nodes this indexes
	all          *sortedNodes // sorted by ID, built on first read
	byNodeKey    graph.Grouped[types.NodeID, *types.Node, key.NodePublic]
	byMachineKey graph.Grouped[types.NodeID, *types.Node, key.MachinePublic]
	// byUser holds user-owned nodes; tagged nodes are owned by their tags.
	byUser graph.Grouped[types.NodeID, *types.Node, types.UserID]
	// advertisers holds, per non-exit prefix, the online nodes approving
	// it: the candidates of its primary-route election.
	advertisers graph.Grouped[types.NodeID, *types.Node, netip.Prefix]
	// approvers also retains offline and expired routers for unavailable-route fallback.
	approvers graph.Grouped[types.NodeID, *types.Node, netip.Prefix]
	// routed holds, under true, the nodes serving any approved route.
	routed graph.Grouped[types.NodeID, *types.Node, bool]
	// byName holds the nodes under their lower-cased given name: DNS is
	// case-insensitive.
	byName graph.Grouped[types.NodeID, *types.Node, string]
	// byUserCopy holds every node carrying a copy of a user, tagged ones
	// too, under that user's ID: the nodes a change to the user rewrites.
	byUserCopy graph.Grouped[types.NodeID, *types.Node, uint]
}

// policyNodes is the node list as the policy reads it. It changes only
// when a node joins, leaves or changes a field the policy reads
// ([types.NodeView.HasPolicyChange]); keeping the older views otherwise is
// what spares an endpoint update a policy compile. gen counts the lists,
// from the nodes it was last checked against.
//
// This cutoff, [graph.Changes] and the peer-class maps decide what a node
// change recomputes, and their tests cover it. Upstream's
// node_recompute_test.go tested NodeNeedsPeerRecompute, a per-node
// predicate the graph core does not have.
type policyNodes struct {
	list views.Slice[types.NodeView]
	from *nodeMap
	gen  uint64
}

// capsMap holds each node's policy capabilities.
type capsMap = graph.Map[types.NodeID, tailcfg.NodeCapMap]

func sameCaps(a, b tailcfg.NodeCapMap) bool { return reflect.DeepEqual(a, b) }

// compiledPolicy is the policy compiled against the users and nodes of a
// snapshot. When a later compile fails, the last good one keeps serving
// and err records why.
type compiledPolicy struct {
	pm  policy.PolicyManager
	err error
}

// newWorld builds the graph and publishes its first snapshot with the
// options a configuration that sets none gets (see [optionsOf]). It fails
// when the policy does not compile against users and nodes.
func newWorld(nodes types.Nodes, users []types.User, polSrc []byte, dns types.DNSView) (*world, error) {
	return newWorldMode(nodes, users, polSrc, dns, optionsOf(types.PolicyConfig{}))
}

// worldOptions are the policy options a world is built with, fixed for its
// life.
type worldOptions struct {
	capSources   bool // policy.capability_sources
	filterChunks bool // policy.filter_chunks
}

// TestCapabilitySourcesEnv, set to a boolean in a test binary's
// environment, decides policy.capability_sources in every world built from
// a configuration that leaves the option off (NewState, newWorld); unset,
// such a world takes the production default. With [TestFilterChunksEnv] it picks
// any combination for the tests that pin neither:
// `make test-options CAPABILITY_SOURCES=false FILTER_CHUNKS=true`.
// Production binaries never read it.
const TestCapabilitySourcesEnv = "HEADSCALE_TEST_CAPABILITY_SOURCES"

// TestFilterChunksEnv is [TestCapabilitySourcesEnv] for
// policy.filter_chunks.
const TestFilterChunksEnv = "HEADSCALE_TEST_FILTER_CHUNKS"

// optionsOf returns the options cfg sets. In a test binary an option cfg
// leaves off follows its switch, or the production default while the
// switch is unset: a configuration literal leaves both off, and tests
// should run what production runs. So a test pins an option on through
// its configuration or its switch, and off only through its switch.
func optionsOf(cfg types.PolicyConfig) worldOptions {
	o := worldOptions{capSources: cfg.CapabilitySources, filterChunks: cfg.FilterChunks}
	if !testing.Testing() {
		return o
	}

	def := config.Default().Policy
	o.capSources = o.capSources || switchForTest(TestCapabilitySourcesEnv, def.CapabilitySources)
	o.filterChunks = o.filterChunks || switchForTest(TestFilterChunksEnv, def.FilterChunks)

	return o
}

// switchForTest reports the boolean env holds, or def when it is unset; a
// value that is no boolean panics.
func switchForTest(env string, def bool) bool {
	v := os.Getenv(env)
	if v == "" {
		return def
	}

	on, err := strconv.ParseBool(v)
	if err != nil {
		panic(fmt.Sprintf("%s=%q: %v", env, v, err))
	}

	return on
}

// newWorldMode is [newWorld] with the options o, as given.
func newWorldMode(nodes types.Nodes, users []types.User, polSrc []byte, dns types.DNSView, o worldOptions) (*world, error) {
	g := graph.New()
	w := &world{
		g: g, full: make(chan struct{}, 1), beforePolicyCommit: func() {},
		capSources: o.capSources, filterChunks: o.filterChunks,
	}

	byID := uniqueGivenNames(nodes)

	table := graph.NewMap(graph.Same[*types.Node], byID)

	w.nodes = g.NewInput("nodes", table, graph.Same[*nodeMap])
	// Users are refreshed on every registration; an unchanged list must not
	// recompile the policy.
	w.users = g.NewInput("users", slices.Clone(users), slices.Equal[[]types.User])

	// The policy reads users only through fields a compile resolves, so a
	// display name or picture change does not recompile it.
	w.policyUsers = graph.NewDerived(g, "policy-users", types.SamePolicyUsers,
		func(s *graph.Snapshot, _ []types.User) []types.User { return s.Get(w.users) })
	w.policySrc = g.NewInput("policy-source", polSrc, graph.Never[[]byte])
	// The DERP map is refreshed on a timer and DNS by the extra-records
	// watcher; an unchanged value must not wake every session.
	w.derpMap = g.NewInput("derp-map", (*tailcfg.DERPMap)(nil), sameDERPMap)
	w.dns = g.NewInput("dns", dns, types.DNSView.Equal)

	w.index = graph.NewDerived(g, "index", graph.Same[*nodeIndex],
		func(s *graph.Snapshot, prev *nodeIndex) *nodeIndex {
			return updateIndex(prev, s.Get(w.nodes))
		})

	w.policyNodes = graph.NewDerived(g, "policy-nodes", samePolicyNodes,
		func(s *graph.Snapshot, prev policyNodes) policyNodes {
			nodes := s.Get(w.nodes)
			if prev.from != nil && !policyFactsChanged(prev.from, nodes) {
				return policyNodes{list: prev.list, from: nodes, gen: prev.gen}
			}

			return policyNodes{list: views.SliceOf(s.Get(w.index).all.get()), from: nodes, gen: prev.gen + 1}
		})

	w.policy = graph.NewDerived(g, "policy", graph.Same[*compiledPolicy],
		func(s *graph.Snapshot, prev *compiledPolicy) *compiledPolicy {
			src := s.Get(w.policySrc)
			users := s.Get(w.policyUsers)
			nodes := s.Get(w.policyNodes).list

			var last policy.PolicyManager
			if prev != nil {
				last = prev.pm
			}

			pm, err := policy.NewPolicyManagerFrom(last, src, users, nodes)
			if err != nil {
				policyCompiles.WithLabelValues("error").Inc()

				log.Error().Err(err).Msg("compiling policy; keeping the last good policy")

				return &compiledPolicy{pm: last, err: err}
			}

			policyCompiles.WithLabelValues("ok").Inc()

			if pmv2, ok := pm.(*policyv2.PolicyManager); ok && last != nil && policyAudit() {
				err := pmv2.Audit(src, users, nodes)
				if err != nil {
					policyAuditFailures.Add(1)
					log.Error().Err(err).Msg("policy audit")
				}
			}

			return &compiledPolicy{pm: pm}
		})

	w.nodeCaps = graph.NewDerived(g, "node-caps", graph.Same[*capsMap], w.deriveNodeCaps)
	w.effectiveDERP = graph.NewDerived(g, "effective-derp", sameDERPMap, func(s *graph.Snapshot, _ *tailcfg.DERPMap) *tailcfg.DERPMap {
		configured := s.Get(w.derpMap)

		pm := s.Get(w.policy).pm
		if pm == nil {
			return configured
		}

		return derp.ApplyPolicy(configured, pm.DERPMap())
	})

	// From the compile in force, not the document: a compile that fails
	// keeps serving the last good policy, for SSH, node attributes, tag
	// owners, auto-approvers and DERP too, and membership must describe the
	// policy served, so one verdict decides for all. A recompile of the same
	// document reuses its parse, so node writes reach no further than here.
	w.selectors = graph.NewDerived(g, "selectors", graph.Same[*policyv2.Selectors],
		func(s *graph.Snapshot, prev *policyv2.Selectors) *policyv2.Selectors {
			pm, _ := s.Get(w.policy).pm.(*policyv2.PolicyManager)

			return policyv2.SelectorsFor(prev, pm)
		})
	w.userSets = graph.NewDerived(g, "user-sets", graph.Same[*policyv2.UserSets],
		func(s *graph.Snapshot, prev *policyv2.UserSets) *policyv2.UserSets {
			return policyv2.NewUserSets(prev, s.Get(w.selectors), s.Get(w.policyUsers))
		})
	w.roles = graph.NewDerived(g, "roles", policyv2.Roles.Same, func(s *graph.Snapshot, prev policyv2.Roles) policyv2.Roles {
		// A changed user's nodes all carry its copy.
		holders := func(uid uint) []types.NodeID {
			ids, _ := s.Get(w.index).byUserCopy.Groups.Get(uid)

			return ids
		}

		return prev.Update(s.Get(w.userSets), s.Get(w.nodes), holders)
	})
	w.postings = graph.NewDerived(g, "postings", policyv2.Postings.Same,
		func(s *graph.Snapshot, prev policyv2.Postings) policyv2.Postings { return prev.Update(s.Get(w.roles)) })
	w.templates = graph.NewDerived(g, "templates", graph.Same[*policyv2.Templates],
		func(s *graph.Snapshot, prev *policyv2.Templates) *policyv2.Templates {
			return policyv2.BuildTemplates(prev, s.Get(w.selectors))
		})
	// From the nodes, not the policy's list: a list is rebuilt per change
	// and a join would walk every node's routes.
	w.approvals = graph.NewDerived(g, "subnet-approvals", policyv2.SubnetApprovals.Same,
		func(s *graph.Snapshot, prev policyv2.SubnetApprovals) policyv2.SubnetApprovals {
			return prev.Update(s.Get(w.nodes))
		})
	// From the nodes, as roles: a write that moves no address, route, tag
	// or user is cut off there and reaches neither classes nor via.
	w.sides = graph.NewDerived(g, "sides", policyv2.Sides.Same, func(s *graph.Snapshot, prev policyv2.Sides) policyv2.Sides {
		return policyv2.UpdateSides(prev, s.Get(w.templates), s.Get(w.roles), s.Get(w.postings), s.Get(w.approvals), s.Get(w.nodes))
	})
	// Over the policy's node list, not the nodes: the addresses of members
	// are policy facts, and an endpoint write must keep every filter
	// served. Building is left to the first session that reads one, and
	// filters the change cannot reach are carried over; the sides say who
	// receives a rule.
	if w.capSources {
		// From the nodes and the policy's caps: what a node announces and
		// what its client is are no policy facts, yet decide the form of
		// its filter.
		w.receivers = graph.NewDerived(g, "receivers", policyv2.Receivers.Same,
			func(s *graph.Snapshot, prev policyv2.Receivers) policyv2.Receivers {
				return prev.Update(s.Get(w.nodes), s.Get(w.nodeCaps))
			})
		w.stamps = graph.NewDerived(g, "stamps", sameStamps, w.deriveStamps)
		w.renderCaps = graph.NewDerived(g, "render-caps", sameRenderCaps, w.deriveRenderCaps)
		w.holders = graph.NewDerived(g, "address-holders", sameHolders, w.deriveHolders)
	}

	// Not from the receivers: a node's facts choose which of its two forms
	// it is served when its filter is read, so a flip touches no other
	// node's filter and builds nothing.
	mode := policyv2.AddressSources
	if w.capSources {
		mode = policyv2.CapabilitySources
	}

	w.filters = graph.NewDerived(g, "filters", graph.Same[*policyv2.Filters],
		func(s *graph.Snapshot, prev *policyv2.Filters) *policyv2.Filters {
			return policyv2.FollowFiltersFor(mode, prev, s.Get(w.templates), s.Get(w.postings), s.Get(w.approvals), s.Get(w.policyNodes).list, s.Get(w.sides))
		})
	w.peers = graph.NewDerived(g, "peers", (*policyv2.PeerClasses).SameKeyed,
		func(s *graph.Snapshot, prev *policyv2.PeerClasses) *policyv2.PeerClasses {
			return policyv2.RolePeers(prev, s.Get(w.sides))
		})
	w.viaPlan = graph.NewDerived(g, "via-plan", policyv2.ViaPlans.Same, func(s *graph.Snapshot, prev policyv2.ViaPlans) policyv2.ViaPlans {
		return policyv2.UpdateViaPlans(prev, s.Get(w.sides))
	})
	w.primaries = graph.NewDerived(g, "primaries", samePrimaries, w.electPrimaries)
	// What the routes every viewer is sent read besides the viewer, the
	// peer and its routes' cover: when it moves, every routed peer renders
	// again for every viewer.
	w.routeRules = graph.NewDerived(g, "route-rules", policyv2.RouteRules.Same,
		func(s *graph.Snapshot, _ policyv2.RouteRules) policyv2.RouteRules {
			return s.Get(w.sides).RouteRules(s.Get(w.viaPlan).Plan)
		})

	// Registered only under the audit, so once, here, where the compile
	// audits read the knob at every compile: a derived cell is recomputed
	// at every commit that changes what it read, whether or not anything
	// reads it, and this one reads the nodes; production must not carry
	// it, and a graph takes no cells once it runs. Setting the knob on a
	// running server therefore starts the compile audits only.
	if policyAudit() {
		w.auditing = true
		w.membershipAudit = graph.NewDerived(g, "membership-audit",
			func(membershipAudit, membershipAudit) bool { return true }, w.auditMembership)
		w.filterAudit = graph.NewDerived(g, "filter-audit", func(filterAudit, filterAudit) bool { return true }, w.auditFilters)
		w.sidesAudit = graph.NewDerived(g, "sides-audit", func(sidesAudit, sidesAudit) bool { return true }, w.auditSides)
	}

	snap, err := g.Update(func(*graph.Tx) error { return nil })
	if err != nil {
		return nil, err
	}

	if cp := snap.Get(w.policy); cp.pm == nil {
		return nil, fmt.Errorf("compiling policy: %w", cp.err)
	}

	worldNodes.Set(float64(table.Len()))

	return w, nil
}

// deriveNodeCaps is the node-caps cell: each node's capability map from
// the compiled policy, editing prev so unchanged nodes keep their entry.
func (w *world) deriveNodeCaps(s *graph.Snapshot, prev *capsMap) *capsMap {
	// A first compile that failed has no policy; newWorld
	// returns its error.
	pm := s.Get(w.policy).pm
	if pm == nil {
		return prev
	}

	caps := pm.NodeCapMaps()
	if prev == nil {
		return graph.NewMap(sameCaps, caps)
	}

	e := prev.Edit()
	for id, c := range caps {
		if old, ok := prev.Get(id); !ok || !sameCaps(old, c) {
			e.Set(id, c)
		}
	}

	for id := range prev.All() {
		if _, ok := caps[id]; !ok {
			e.Delete(id)
		}
	}

	return e.Done()
}

// stampsMap holds the source capabilities each node holds, from the role
// sets and templates it was built for.
type stampsMap struct {
	m     *graph.Map[types.NodeID, policyv2.Stamps]
	roles policyv2.Roles
	t     *policyv2.Templates
}

func sameStampSets(a, b policyv2.Stamps) bool { return slices.Equal(a, b) }

func sameStamps(a, b stampsMap) bool { return a.m == b.m }

// deriveStamps is the stamps cell: each node's stamps from its role set,
// recomputed for the nodes whose role set moved, or for every node when
// the templates did.
func (w *world) deriveStamps(s *graph.Snapshot, prev stampsMap) stampsMap {
	roles, t := s.Get(w.roles), s.Get(w.templates)
	next := stampsMap{m: prev.m, roles: roles, t: t}

	if next.m == nil {
		next.m = graph.NewMap[types.NodeID](sameStampSets, nil)
	}

	var changed []types.NodeID

	switch {
	case prev.t != t:
		// Edited, not built anew, so readers diff it through its log.
		for id := range roles.All() {
			changed = append(changed, id)
		}

		for id := range next.m.All() {
			changed = append(changed, id)
		}
	case !prev.roles.Same(roles):
		changed = graph.Changes(prev.roles.Sets(), roles.Sets())
	}

	if len(changed) == 0 {
		return next
	}

	e := next.m.Edit()

	for _, id := range changed {
		rs, ok := roles.Of(id)
		if stamps := t.StampsOf(rs); ok && len(stamps) > 0 {
			e.Set(id, stamps)
		} else {
			e.Delete(id)
		}
	}

	next.m = e.Done()

	return next
}

// renderCaps holds each node's capabilities as it is rendered, to peers
// and to itself: the policy's, and its stamps. from and stamps are what it
// was merged from.
type renderCaps struct {
	m      *capsMap
	from   *capsMap
	stamps *graph.Map[types.NodeID, policyv2.Stamps]
}

func sameRenderCaps(a, b renderCaps) bool { return a.m == b.m }

// deriveRenderCaps merges the policy's capabilities and the stamps, for the
// nodes either moved for.
func (w *world) deriveRenderCaps(s *graph.Snapshot, prev renderCaps) renderCaps {
	caps, stamps := s.Get(w.nodeCaps), s.Get(w.stamps).m
	next := renderCaps{m: prev.m, from: caps, stamps: stamps}

	if next.m == nil {
		next.m = graph.NewMap[types.NodeID](sameCaps, nil)
	}

	changed := slices.Concat(graph.Changes(prev.from, caps), graph.Changes(prev.stamps, stamps))
	if len(changed) == 0 {
		return next
	}

	e := next.m.Edit()

	for _, id := range changed {
		c, hasCaps := caps.Get(id)
		st, hasStamps := stamps.Get(id)

		if !hasCaps && !hasStamps {
			e.Delete(id)

			continue
		}

		e.Set(id, policyv2.WithStamps(c, st))
	}

	next.m = e.Done()

	return next
}

// addressHolders holds the nodes holding each address, from nodes.
type addressHolders struct {
	m     *graph.Map[netip.Addr, []types.NodeID]
	nodes *nodeMap
}

func sameHolders(a, b addressHolders) bool { return a.m == b.m }

// deriveHolders moves the nodes whose addresses changed.
func (w *world) deriveHolders(s *graph.Snapshot, prev addressHolders) addressHolders {
	nodes := s.Get(w.nodes)
	next := addressHolders{m: prev.m, nodes: nodes}

	if next.m == nil {
		next.m = graph.NewMap[netip.Addr](slices.Equal[[]types.NodeID], nil)
	}

	changed := graph.Changes(prev.nodes, nodes)
	if len(changed) == 0 {
		return next
	}

	e := next.m.Edit()

	for _, id := range changed {
		var was, is []netip.Addr

		if n, ok := prev.nodes.Get(id); ok {
			was = n.IPs()
		}

		if n, ok := nodes.Get(id); ok {
			is = n.IPs()
		}

		for _, a := range was {
			if slices.Contains(is, a) {
				continue
			}

			ids, _ := e.Get(a)
			if ids = slices.DeleteFunc(slices.Clone(ids), func(h types.NodeID) bool { return h == id }); len(ids) > 0 {
				e.Set(a, ids)
			} else {
				e.Delete(a)
			}
		}

		for _, a := range is {
			if ids, _ := e.Get(a); !slices.Contains(ids, id) {
				e.Set(a, append(slices.Clone(ids), id))
			}
		}
	}

	next.m = e.Done()

	return next
}

// membershipAudit is the revision the membership audit last checked, and
// the selectors whose table it last found complete.
type membershipAudit struct {
	rev   uint64
	table *policyv2.Selectors
}

// auditMembership checks the membership cells against a build from
// scratch and against the compile's resolution of every selector, at every
// commit that changes the policy, the users or the nodes.
func (w *world) auditMembership(s *graph.Snapshot, prev membershipAudit) membershipAudit {
	membershipAuditRuns.Add(1)

	cp := s.Get(w.policy)
	pm, _ := cp.pm.(*policyv2.PolicyManager)
	sel := s.Get(w.selectors)

	_, err := policyv2.AuditMembership(policyv2.Membership{
		Selectors: sel,
		UserSets:  s.Get(w.userSets),
		Roles:     s.Get(w.roles),
		Postings:  s.Get(w.postings),
		Users:     s.Get(w.policyUsers),
		Nodes:     s.Get(w.nodes),
		Policy:    pm,
		Current:   cp.err == nil,
		// The completeness walk costs the policy's size; a node write
		// leaves the selectors it checked as they were.
		TableAudited: prev.table == sel,
	})
	if err != nil {
		policyAuditFailures.Add(1)
		log.Error().Err(err).Msg("policy audit: membership")

		sel = nil
	}

	return membershipAudit{rev: s.Rev(), table: sel}
}

// MembershipAudited reports, for tests, whether the membership audit
// checked the membership of s at the last commit that changed it: false
// without the audit.
func (s *Snapshot) MembershipAudited() bool {
	if !s.w.auditing {
		return false
	}

	last := uint64(0)
	for _, rev := range []uint64{
		graph.ChangedAt(s.s, s.w.policy), graph.ChangedAt(s.s, s.w.policyUsers), graph.ChangedAt(s.s, s.w.nodes),
		graph.ChangedAt(s.s, s.w.selectors), graph.ChangedAt(s.s, s.w.userSets),
		graph.ChangedAt(s.s, s.w.roles), graph.ChangedAt(s.s, s.w.postings),
	} {
		last = max(last, rev)
	}

	return s.s.Get(s.w.membershipAudit).rev == last
}

// filterAudit is the revision the filter audit last checked, and the
// templates it last found equal to a build from scratch.
type filterAudit struct {
	rev       uint64
	templates *policyv2.Templates
}

// auditFilters checks, at every commit that changes the compile, its users
// or node list, the templates, the postings or the approved routes, that
// every node's filter an expansion built here gives equals the compile's,
// as does the global filter. It reads the policy's node list, not the
// nodes: no input of either side changes on an endpoint or health write,
// so neither does the verdict, and the audit costs nothing there.
//
// It leaves the served filters alone: reading them here would work out
// every change and cut every filter at the commit, so the audit would never
// see the filters served the way production serves them, carried across
// commits nobody read. [Snapshot.FilterForNode] holds each served filter,
// when read, to one cut afresh instead.
func (w *world) auditFilters(s *graph.Snapshot, prev filterAudit) filterAudit {
	filterAuditRuns.Add(1)

	cp := s.Get(w.policy)
	pm, _ := cp.pm.(*policyv2.PolicyManager)
	templates := s.Get(w.templates)

	_, err := policyv2.AuditFilters(policyv2.FilterAudit{
		Templates: templates,
		Postings:  s.Get(w.postings),
		Approvals: s.Get(w.approvals),
		Nodes:     s.Get(w.policyNodes).list,
		Users:     s.Get(w.policyUsers),
		Policy:    pm,
		Current:   cp.err == nil,
		// A build from scratch costs the policy's size; a node write
		// leaves the templates it checked as they were.
		TemplatesAudited: prev.templates == templates,
	})
	if err != nil {
		policyAuditFailures.Add(1)
		log.Error().Err(err).Msg("policy audit: filter")

		templates = nil
	}

	return filterAudit{rev: s.Rev(), templates: templates}
}

// FilterAudited reports, for tests, whether the filter audit checked s at
// the last commit that changed what it reads: false without the audit.
func (s *Snapshot) FilterAudited() bool {
	if !s.w.auditing {
		return false
	}

	last := uint64(0)
	for _, rev := range []uint64{
		graph.ChangedAt(s.s, s.w.policy), graph.ChangedAt(s.s, s.w.policyUsers), graph.ChangedAt(s.s, s.w.policyNodes),
		graph.ChangedAt(s.s, s.w.templates), graph.ChangedAt(s.s, s.w.postings), graph.ChangedAt(s.s, s.w.approvals),
	} {
		last = max(last, rev)
	}

	return s.s.Get(s.w.filterAudit).rev == last
}

// sidesAudit is what the sides audit last checked. pairs holds the inputs
// of its last all-pairs check, made at pairsRev; routes reports that the
// role-based routes were held against the compile then, which needs it
// current. primaries and elected are what the last election check read,
// made at electRev. A check that did not run leaves its part as it was,
// so the next commit that can run it does.
type sidesAudit struct {
	pairs    sidesPairs
	pairsRev uint64
	routes   bool

	primaries uint64
	elected   *policyv2.ViaPlan
	electRev  uint64
}

// sidesPairs are the inputs of the all-pairs check.
type sidesPairs struct {
	policy   *compiledPolicy
	nodesGen uint64
	sides    policyv2.Sides
	peers    *policyv2.PeerClasses
	via      *policyv2.ViaPlan
}

func (w *world) sidesPairsOf(s *graph.Snapshot) sidesPairs {
	return sidesPairs{
		policy: s.Get(w.policy), nodesGen: s.Get(w.policyNodes).gen,
		sides: s.Get(w.sides), peers: s.Get(w.peers), via: s.Get(w.viaPlan).Plan,
	}
}

func (p sidesPairs) same(o sidesPairs) bool {
	return p.policy == o.policy && p.nodesGen == o.nodesGen && p.sides.Same(o.sides) && p.peers == o.peers && p.via == o.via
}

// auditSides holds the role-based visibility, route access and via against
// builds from scratch and against the compile, for every node and pair, at
// every commit that changes what either side reads of the policy, its node
// list or the role-based cells; and the via elections against the plan at
// every commit that moves an election. The pairs are quadratic, so they
// run at the cadence of policy facts only: a health or online write moves
// an election, never a side, and is checked by the election part alone,
// which reads the nodes only then and allocates nothing while it agrees.
//
// While the document in force is refused, the role-based cells follow the
// current membership under the last good policy, as the selectors do: the
// pairs are held against that document compiled afresh over the current
// nodes. The routes and elections compare with the compile in force, which
// describes older nodes then; they wait for a current one.
func (w *world) auditSides(s *graph.Snapshot, prev sidesAudit) sidesAudit {
	cp := s.Get(w.policy)
	pn := s.Get(w.policyNodes)
	in := w.sidesPairsOf(s)
	prim := s.Get(w.primaries)

	pm, _ := cp.pm.(*policyv2.PolicyManager)
	current := cp.err == nil
	next := prev

	fail := func(what string, err error) {
		policyAuditFailures.Add(1)
		log.Error().Err(err).Msg("policy audit: " + what)
	}

	if pm != nil && (prev.pairsRev == 0 || !prev.pairs.same(in) || current && !prev.routes) {
		sidesAuditRuns.Add(1)

		_, err := policyv2.AuditSides(policyv2.SidesAudit{
			Templates: s.Get(w.templates), Roles: s.Get(w.roles), Postings: s.Get(w.postings),
			Approvals: s.Get(w.approvals), Nodes: s.Get(w.nodes),
			Sides: in.sides, Peers: in.peers, Via: in.via,
			List: pn.list, Users: s.Get(w.policyUsers), Policy: pm, Current: current,
		})
		if err != nil {
			fail("sides", err)
		}

		if current {
			err := w.auditRoleRoutes(&Snapshot{s: s, w: w}, pm, pn.list)
			if err != nil {
				fail("role routes", err)
			}
		}

		next.pairs, next.pairsRev, next.routes = in, s.Rev(), current
	}

	if pm != nil && current && (prev.electRev == 0 || prev.primaries != prim.gen || prev.elected != in.via) {
		viaPlanAuditRuns.Add(1)

		nodes := s.Get(w.nodes)
		elect := func(candidates views.Slice[types.NodeID], incumbent types.NodeID) (types.NodeID, bool) {
			return electViaPrimary(nodes, candidates, incumbent)
		}

		if !in.via.Elects(prim.via, elect) {
			fail("via plan", errViaPlanElection)
		}

		// The oracle: the compile's own scopes elect what is served.
		if !pm.ElectsVia(prim.via, elect) {
			fail("via election", errCompiledElection)
		}

		next.primaries, next.elected, next.electRev = prim.gen, in.via, s.Rev()
	}

	return next
}

var (
	errViaPlanElection  = errors.New("the election differs from one over the via plan")
	errCompiledElection = errors.New("the election differs from one over the compile's via scopes")
	errRoleRoutes       = errors.New("served routes differ from the compile's")
)

// auditRoleRoutes holds the routes every viewer is served for every peer
// against the compile's: route access by the viewer's matchers, and via
// steering by the compile's own scopes, elected afresh.
func (w *world) auditRoleRoutes(snap *Snapshot, pm *policyv2.PolicyManager, list views.Slice[types.NodeView]) error {
	nodes := snap.nodes()
	compiled := pm.ElectViaAfresh(nil, func(candidates views.Slice[types.NodeID], incumbent types.NodeID) (types.NodeID, bool) {
		return electViaPrimary(nodes, candidates, incumbent)
	})

	prim := snap.s.Get(w.primaries)

	for _, viewer := range list.All() {
		matchers, err := pm.MatchersForNode(viewer)
		if err != nil {
			return err
		}

		for _, peer := range list.All() {
			want := w.compiledRoutesForPeer(prim, compiled, viewer, peer, matchers)
			got := snap.RoutesForPeer(viewer, peer)

			if !slices.Equal(want, got) {
				return fmt.Errorf("%w: node %d through %d: %v, the compile's %v", errRoleRoutes, viewer.ID(), peer.ID(), got, want)
			}
		}
	}

	return nil
}

// CompiledRoutesForPeer is what [Snapshot.RoutesForPeer] gives as the
// compile decides it: route access by viewer's matchers, via steering by the
// compile's own scopes elected afresh. It is the oracle the audit and tests
// hold the served routes against, written apart from them; nothing serves
// it.
func (s *Snapshot) CompiledRoutesForPeer(viewer, peer types.NodeView) ([]netip.Prefix, error) {
	pm, ok := s.Policy().(*policyv2.PolicyManager)
	if !ok {
		return nil, errNotV2Policy
	}

	matchers, err := pm.MatchersForNode(viewer)
	if err != nil {
		return nil, err
	}

	nodes := s.nodes()
	via := pm.ElectViaAfresh(nil, func(candidates views.Slice[types.NodeID], incumbent types.NodeID) (types.NodeID, bool) {
		return electViaPrimary(nodes, candidates, incumbent)
	})

	return s.w.compiledRoutesForPeer(s.s.Get(s.w.primaries), via, viewer, peer, matchers), nil
}

// compiledRoutesForPeer is [Snapshot.RoutesForPeer] as the compile decides it:
// route access by viewer's matchers, steering by via, the compile's
// elections. Written apart from RoutesForPeer, so the audit sees a mistake in
// either.
func (w *world) compiledRoutesForPeer(prim primaryRoutes, via *policyv2.ViaRoutes, viewer, peer types.NodeView, matchers []matcher.Match) []netip.Prefix {
	steer := via.ForPeer(viewer, peer)
	primaries := slices.Clone(prim.byNode[peer.ID()])
	candidates := slices.Concat(primaries, peer.ExitRoutes())

	var reduced []netip.Prefix

	if len(steer.Include) == 0 && len(steer.Exclude) == 0 {
		reduced = policy.ReduceRoutes(viewer, candidates, matchers)
	} else {
		candidates = slices.DeleteFunc(candidates, func(p netip.Prefix) bool { return slices.Contains(steer.Exclude, p) })
		reduced = policy.ReduceRoutes(viewer, candidates, matchers)

		for _, p := range steer.Include {
			if !slices.Contains(reduced, p) && (slices.Contains(primaries, p) || !slices.Contains(steer.UsePrimary, p)) {
				reduced = append(reduced, p)
			}
		}
	}

	for _, p := range primaries {
		if slices.Contains(viewer.SubnetRoutes(), p) && !slices.Contains(reduced, p) {
			reduced = append(reduced, p)
		}
	}

	if w.servesRoute != nil {
		reduced = slices.DeleteFunc(reduced, func(p netip.Prefix) bool { return !w.servesRoute(p) })
	}

	return reduced
}

// SidesAudited reports, for tests, whether the sides audit's all-pairs
// check ran on what s holds, its routes included when the compile in force
// is current: false without the audit.
func (s *Snapshot) SidesAudited() bool {
	if !s.w.auditing {
		return false
	}

	a := s.s.Get(s.w.sidesAudit)

	return a.pairsRev != 0 && a.pairs.same(s.w.sidesPairsOf(s.s)) && (a.routes || s.s.Get(s.w.policy).err != nil)
}

// ViaElectionAudited reports, for tests, whether the sides audit held the
// elections s holds against its via plan: false without the audit, and
// while the document in force is refused.
func (s *Snapshot) ViaElectionAudited() bool {
	if !s.w.auditing {
		return false
	}

	a := s.s.Get(s.w.sidesAudit)

	return a.electRev != 0 && a.primaries == s.s.Get(s.w.primaries).gen && a.elected == s.s.Get(s.w.viaPlan).Plan
}

// updateIndex returns the index of nodes, moving only the nodes changed
// since prev was built.
func updateIndex(prev *nodeIndex, nodes *nodeMap) *nodeIndex {
	var p nodeIndex
	if prev != nil {
		p = *prev
	}

	return &nodeIndex{
		from: nodes,
		all:  p.all.next(nodes),
		byNodeKey: graph.GroupBy(p.byNodeKey, nodes, func(_ types.NodeID, n *types.Node) []key.NodePublic {
			return []key.NodePublic{n.NodeKey}
		}, nil),
		byMachineKey: graph.GroupBy(p.byMachineKey, nodes, func(_ types.NodeID, n *types.Node) []key.MachinePublic {
			return []key.MachinePublic{n.MachineKey}
		}, nil),
		byUser: graph.GroupBy(p.byUser, nodes, func(_ types.NodeID, n *types.Node) []types.UserID {
			if n.IsTagged() {
				return nil
			}

			return []types.UserID{n.TypedUserID()}
		}, nil),
		// The route indexes skip writes that leave the route facts alone:
		// deriving a router's routes costs its route count, per side.
		routed: graph.GroupBy(p.routed, nodes, func(_ types.NodeID, n *types.Node) []bool {
			if len(n.AllApprovedRoutes()) == 0 {
				return nil
			}

			return []bool{true}
		}, (*types.Node).SameRouteFacts),
		approvers: graph.GroupBy(p.approvers, nodes, func(_ types.NodeID, n *types.Node) []netip.Prefix { return electionRoutes(n) }, (*types.Node).SameRouteFacts),
		advertisers: graph.GroupBy(p.advertisers, nodes, func(_ types.NodeID, n *types.Node) []netip.Prefix {
			if !servesRoutes(n) {
				return nil
			}

			return electionRoutes(n)
		}, func(was, is *types.Node) bool {
			return was.Online() == is.Online() && was.View().Expiry().GetOr(time.Time{}).Equal(is.View().Expiry().GetOr(time.Time{})) && was.SameRouteFacts(is)
		}),
		byName: graph.GroupBy(p.byName, nodes, func(_ types.NodeID, n *types.Node) []string {
			return []string{strings.ToLower(n.GivenName)}
		}, func(was, is *types.Node) bool { return was.GivenName == is.GivenName }),
		byUserCopy: graph.GroupBy(p.byUserCopy, nodes, func(_ types.NodeID, n *types.Node) []uint {
			var ids []uint
			if n.User != nil {
				ids = append(ids, n.User.ID)
			}

			if n.AuthKey != nil && n.AuthKey.User != nil && (n.User == nil || n.User.ID != n.AuthKey.User.ID) {
				ids = append(ids, n.AuthKey.User.ID)
			}

			return ids
		}, func(was, is *types.Node) bool {
			userID := func(n *types.Node) uint {
				if n.User != nil {
					return n.User.ID
				}

				return 0
			}
			keyUserID := func(n *types.Node) uint {
				if n.AuthKey != nil && n.AuthKey.User != nil {
					return n.AuthKey.User.ID
				}

				return 0
			}

			return userID(was) == userID(is) && keyUserID(was) == keyUserID(is)
		}),
	}
}

// electionRoutes are the prefixes a node is a primary-route candidate for
// when online: its approved, announced routes, exits aside.
func electionRoutes(n *types.Node) []netip.Prefix {
	return slices.DeleteFunc(n.AllApprovedRoutes(), tsaddr.IsExitRoute)
}

// patchSorted returns the views of to sorted by ID, given all, the sorted
// views of from.
// sortedNodes is an index's nodes sorted by ID, built on first read: most
// commits change nodes nobody lists, and keeping the list current copied
// every node per commit. An unbuilt list patches from the last built one,
// so it holds at most one older list.
type sortedNodes struct {
	from *nodeMap

	mu    sync.Mutex
	built bool
	list  []types.NodeView
	base  *sortedNodes // a built list to patch from; nil once built
}

// next returns the unbuilt list of nodes, patching from s or from the list
// s itself patches from. s may be nil.
func (s *sortedNodes) next(nodes *nodeMap) *sortedNodes {
	n := &sortedNodes{from: nodes}

	if s != nil {
		s.mu.Lock()
		if s.built {
			n.base = s
		} else {
			n.base = s.base
		}
		s.mu.Unlock()
	}

	return n
}

// get returns the nodes sorted by ID.
func (s *sortedNodes) get() []types.NodeView {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.built {
		var (
			from *nodeMap
			all  []types.NodeView
		)

		if s.base != nil {
			from, all = s.base.from, s.base.get()
		}

		s.list, s.built, s.base = patchSorted(from, all, s.from), true, nil
	}

	return s.list
}

func patchSorted(from *nodeMap, all []types.NodeView, to *nodeMap) []types.NodeView {
	byID := func(nv types.NodeView, id types.NodeID) int { return cmp.Compare(nv.ID(), id) }

	if from == nil {
		out := make([]types.NodeView, 0, to.Len())
		for _, n := range to.All() {
			out = append(out, n.View())
		}

		slices.SortFunc(out, func(a, b types.NodeView) int { return cmp.Compare(a.ID(), b.ID()) })

		return out
	}

	changed := graph.Changes(from, to)
	if len(changed) == 0 {
		return all
	}

	out := slices.Clone(all)

	for _, id := range changed {
		i, found := slices.BinarySearchFunc(out, id, byID)
		n, ok := to.Get(id)

		switch {
		case found && ok:
			out[i] = n.View()
		case found:
			out = slices.Delete(out, i, i+1)
		case ok:
			out = slices.Insert(out, i, n.View())
		}
	}

	return out
}

func samePolicyNodes(a, b policyNodes) bool { return a.gen == b.gen }

// policyFactsChanged reports whether a node joined, left or changed a
// field the policy reads between from and to.
func policyFactsChanged(from, to *nodeMap) bool {
	for _, id := range graph.Changes(from, to) {
		old, wasOK := from.Get(id)
		n, isOK := to.Get(id)

		if wasOK != isOK || old.View().HasPolicyChange(n.View()) {
			return true
		}
	}

	return false
}

// electionInputChanged reports whether a change between from and to can
// move an election: a router's availability moves the prefixes it names,
// and a policy fact — a join, a leave, tags, addresses, routes — can move
// more. One walk decides exactly what [electionPrefixes] and
// [policyFactsChanged] decide separately. The arms run cheapest first:
// presence, then availability guarded by routes, then the policy facts.
func electionInputChanged(from, to *nodeMap) bool {
	for _, id := range graph.Changes(from, to) {
		old, wasOK := from.Get(id)
		n, isOK := to.Get(id)

		if wasOK != isOK {
			// A join or a leave is a policy fact change.
			return true
		}

		// Availability moves only the prefixes a changed router names: a
		// node without election routes — a plain client, an exit-only
		// router — moves none. Equal route facts, as an endpoint write
		// keeps them, need no route lists built.
		if old.Online() != n.Online() ||
			old.Unhealthy != n.Unhealthy ||
			!old.SessionStart.Equal(n.SessionStart) ||
			!old.View().Expiry().GetOr(time.Time{}).Equal(n.View().Expiry().GetOr(time.Time{})) ||
			!old.SameRouteFacts(n) && !slices.Equal(old.AllApprovedRoutes(), n.AllApprovedRoutes()) {
			if len(electionRoutes(old))+len(electionRoutes(n)) > 0 {
				return true
			}
		}

		if old.View().HasPolicyChange(n.View()) {
			return true
		}
	}

	return false
}

// sameUserForNodes reports whether a node holding user a needs no copy of
// b: they differ at most in timestamps, which no map or policy reads. A
// login bumping UpdatedAt then rewrites none of the user's nodes.
func sameUserForNodes(a, b types.User) bool {
	a.CreatedAt, a.UpdatedAt, a.DeletedAt = b.CreatedAt, b.UpdatedAt, b.DeletedAt

	return a == b
}

// electPrimaries re-elects the prefixes a change can move. prev is a
// per-commit copy of the cell's boxed value, so fields may be reassigned
// here, but maps shared with published snapshots (routes, byNode) must
// never be mutated in place.
func (w *world) electPrimaries(s *graph.Snapshot, prev primaryRoutes) primaryRoutes {
	nodes := s.Get(w.nodes)
	// Both are read at every election: the via elections are bound to the
	// sides they steer by, so a commit moving them must rebind.
	plan, sides := s.Get(w.viaPlan).Plan, s.Get(w.sides)

	var (
		touched map[netip.Prefix]struct{}
		next    primaryRoutes
	)

	groups := s.Get(w.index).approvers.Groups

	if prev.from == nil {
		next = newPrimaryRoutes(electPrimaryRoutes(nodes, nil), nodes, prev)
		next.outages = patchOutages(nil, nodes, groups, next.routes, next.routes)
	} else {
		// Only the prefixes a changed router names can elect anew, and,
		// for via, the scopes of a plan that moved: it keeps its identity
		// while its scopes stay.
		touched = electionPrefixes(prev.from, nodes)
		if len(touched) == 0 && plan == prev.via.Plan() {
			prev.from = nodes
			prev.via = prev.via.WithSides(sides)

			return prev
		}

		// The touched prefixes elect anew; the rest keep their winners.
		// The map is cloned only when a winner actually moves, so a
		// touched commit that re-elects everyone allocates nothing.
		routes := prev.routes

		var moved []netip.Prefix

		for p := range touched {
			candidates, _ := groups.Get(p)
			primary, ok := electPrimary(nodes, views.SliceOf(candidates), prev.routes[p])

			cur, had := prev.routes[p]
			if (ok && (!had || cur != primary)) || (!ok && had) {
				if moved == nil {
					routes = maps.Clone(prev.routes)

					w.routesClones.Add(1)
				}

				moved = append(moved, p)

				if ok {
					routes[p] = primary
				} else {
					delete(routes, p)
				}
			}
		}

		// Unmoved winners keep the election as it was; moved ones patch
		// it, so the cost follows the moves, not every route.
		next = prev
		next.from = nodes

		if moved != nil {
			next = prev.patch(routes, moved, nodes)
		}

		// A prefix's outage reads only its primary and advertisers, and a
		// change to either touches the prefix: the rest keep their state.
		next.outages = patchOutages(prev.outages, nodes, groups, routes, touched)
	}

	electRoute := func(candidates views.Slice[types.NodeID], incumbent types.NodeID) (types.NodeID, bool) {
		return electViaPrimary(nodes, candidates, incumbent)
	}

	via, changed := policyv2.ElectViaPlan(prev.via, plan, sides, touched, electRoute)

	// The from-scratch reference for the incremental election above: every
	// scope of the plan elected afresh must give what the world adopted.
	// The sides audit holds it against the compile's scopes as well.
	if policyAudit() {
		policyAuditRuns.Add(1)

		if !plan.Elects(via, electRoute) {
			policyAuditFailures.Add(1)
			log.Error().Msg("policy audit: via election differs from a full one")
		}
	}

	if changed {
		next.gen++
	}

	next.via = via

	return next
}

// primaryRoutes holds global and via-scoped elections from the same snapshot.
type primaryRoutes struct {
	routes map[netip.Prefix]types.NodeID
	// via holds the via elections, bound to the plan that scopes them and
	// the sides that steer by them.
	via *policyv2.ViaRoutes
	// byNode is routes inverted, each node's prefixes sorted.
	byNode map[types.NodeID][]netip.Prefix
	// outages are the prefixes whose primary is unhealthy while no
	// advertiser is healthy, see [hasOutage].
	outages map[netip.Prefix]struct{}
	from    *nodeMap
	// gen changes only when the election result changes, so endpoint
	// writes reach the equality cutoff without comparing every prefix.
	gen uint64
}

// newPrimaryRoutes builds a first election.
func newPrimaryRoutes(routes map[netip.Prefix]types.NodeID, from *nodeMap, prev primaryRoutes) primaryRoutes {
	byNode := make(map[types.NodeID][]netip.Prefix)
	for p, id := range routes {
		byNode[id] = append(byNode[id], p)
	}

	for _, ps := range byNode {
		slices.SortFunc(ps, netip.Prefix.Compare)
	}

	return primaryRoutes{routes: routes, byNode: byNode, from: from, gen: prev.gen + 1}
}

// patch returns p with routes, whose winners differ from p's at exactly
// moved. Only the nodes losing or gaining a prefix get new byNode slices;
// the rest share p's, which are never mutated.
func (p primaryRoutes) patch(routes map[netip.Prefix]types.NodeID, moved []netip.Prefix, from *nodeMap) primaryRoutes {
	// Each node losing or gaining prefixes gets its list rebuilt once:
	// editing it prefix by prefix shifts the list for each, which a router
	// failing over all its prefixes pays quadratically. The edits are sized
	// first, so a move allocates per node, not per prefix.
	sizes := make(map[types.NodeID][2]int)

	for _, prefix := range moved {
		if id, ok := p.routes[prefix]; ok {
			n := sizes[id]
			n[0]++
			sizes[id] = n
		}

		if id, ok := routes[prefix]; ok {
			n := sizes[id]
			n[1]++
			sizes[id] = n
		}
	}

	type edit struct{ lost, won []netip.Prefix }

	edits := make(map[types.NodeID]*edit, len(sizes))
	for id, n := range sizes {
		edits[id] = &edit{lost: make([]netip.Prefix, 0, n[0]), won: make([]netip.Prefix, 0, n[1])}
	}

	for _, prefix := range moved {
		if id, ok := p.routes[prefix]; ok {
			edits[id].lost = append(edits[id].lost, prefix)
		}

		if id, ok := routes[prefix]; ok {
			edits[id].won = append(edits[id].won, prefix)
		}
	}

	byNode := maps.Clone(p.byNode)

	for id, e := range edits {
		ps := mergePrefixes(p.byNode[id], e.lost, e.won)
		if len(ps) == 0 {
			delete(byNode, id)
		} else {
			byNode[id] = ps
		}
	}

	return primaryRoutes{routes: routes, byNode: byNode, from: from, gen: p.gen + 1}
}

// mergePrefixes returns sorted has without drop and with add, in a new
// slice; has is shared with older snapshots and never modified. It copies
// the runs of has between edits whole, finding each edit by binary search,
// so a few edits to a long list cost one copy of it. drop should name
// prefixes of has; one it lacks is ignored, and only the capacity hint
// assumes otherwise.
func mergePrefixes(has, drop, add []netip.Prefix) []netip.Prefix {
	slices.SortFunc(drop, netip.Prefix.Compare)
	slices.SortFunc(add, netip.Prefix.Compare)

	out := make([]netip.Prefix, 0, max(0, len(has)-len(drop)+len(add)))
	rest := has

	for len(drop) > 0 || len(add) > 0 {
		// The next edit in order; a prefix both dropped and added is
		// dropped first.
		dropping := len(add) == 0 || len(drop) > 0 && drop[0].Compare(add[0]) <= 0

		next := add
		if dropping {
			next = drop
		}

		at, found := slices.BinarySearchFunc(rest, next[0], netip.Prefix.Compare)
		out = append(out, rest[:at]...)
		rest = rest[at:]

		switch {
		case dropping:
			if found {
				rest = rest[1:]
			}

			drop = drop[1:]
		case found:
			// Already held; kept with the run that follows.
			add = add[1:]
		default:
			out = append(out, add[0])
			add = add[1:]
		}
	}

	return append(out, rest...)
}

// inOutage reports whether p is elected to an unhealthy primary while no
// advertiser is healthy.
func inOutage(nodes *nodeMap, groups *graph.Map[netip.Prefix, []types.NodeID], routes map[netip.Prefix]types.NodeID, p netip.Prefix) bool {
	id, ok := routes[p]
	if !ok {
		return false
	}

	primary, ok := nodes.Get(id)
	if !ok || !primary.Unhealthy {
		return false
	}

	available := func(id types.NodeID) bool { n, ok := nodes.Get(id); return ok && servesRoutes(n) && !n.Unhealthy }
	candidates, _ := groups.Get(p)

	return !slices.ContainsFunc(candidates, available)
}

// patchOutages returns prev with the outage state of prefixes recomputed,
// sharing prev when none moved: it is shared with published snapshots.
func patchOutages[V any](
	prev map[netip.Prefix]struct{},
	nodes *nodeMap,
	groups *graph.Map[netip.Prefix, []types.NodeID],
	routes map[netip.Prefix]types.NodeID,
	prefixes map[netip.Prefix]V,
) map[netip.Prefix]struct{} {
	out, cloned := prev, false

	for p := range prefixes {
		_, was := prev[p]
		if is := inOutage(nodes, groups, routes, p); was == is {
			continue
		}

		if !cloned {
			cloned, out = true, maps.Clone(prev)
			if out == nil {
				out = make(map[netip.Prefix]struct{})
			}
		}

		if was {
			delete(out, p)
		} else {
			out[p] = struct{}{}
		}
	}

	return out
}

func samePrimaries(a, b primaryRoutes) bool { return a.gen == b.gen }

// electionPrefixes returns the prefixes whose election a change between
// from and to can move: those a node approves before or after a change to
// its online state, health or routes.
func electionPrefixes(from, to *nodeMap) map[netip.Prefix]struct{} {
	touched := map[netip.Prefix]struct{}{}

	for _, id := range graph.Changes(from, to) {
		old, wasOK := from.Get(id)
		n, isOK := to.Get(id)

		if wasOK && isOK && old.Online() == n.Online() && old.Unhealthy == n.Unhealthy &&
			old.SessionStart.Equal(n.SessionStart) &&
			old.View().Expiry().GetOr(time.Time{}).Equal(n.View().Expiry().GetOr(time.Time{})) &&
			(old.SameRouteFacts(n) || slices.Equal(old.AllApprovedRoutes(), n.AllApprovedRoutes())) {
			continue
		}

		for _, side := range []*types.Node{old, n} {
			if side == nil {
				continue
			}

			for _, p := range electionRoutes(side) {
				touched[p] = struct{}{}
			}
		}
	}

	return touched
}

// snapshot returns the latest consistent view of the world.
func (w *world) snapshot() *Snapshot {
	return &Snapshot{s: w.g.Snapshot(), w: w}
}

// nodeWrite is one queued change to the node table; see [world.update].
type nodeWrite struct {
	fn   func(nodes *nodeEdit)
	done chan writeResult
}

// writeResult is a committed write's snapshot, or the panic its commit
// raised, which the writer re-raises in its own goroutine.
type writeResult struct {
	snap  *Snapshot
	panic any
}

// update commits fn's edit of the nodes and returns the snapshot holding
// it.
//
// Writes that arrive while a commit runs share the next one (group
// commit): a burst of joins, deletes or endpoint updates costs one policy
// compile and one peer rebuild instead of one each, and an idle write pays
// no wait.
func (w *world) update(fn func(nodes *nodeEdit)) *Snapshot {
	nw := &nodeWrite{fn: fn, done: make(chan writeResult, 1)}

	w.writeMu.Lock()
	w.writes = append(w.writes, nw)
	lead := !w.committing
	w.committing = true

	if w.batchSize > 0 && len(w.writes) >= w.batchSize {
		select {
		case w.full <- struct{}{}:
		default:
		}
	}
	w.writeMu.Unlock()

	if lead {
		w.lead()
	}

	r := <-nw.done
	if r.panic != nil {
		panic(r.panic)
	}

	return r.snap
}

// lingerForBatch waits for writes to batch, as the tuning asks. It runs
// only during an HA outage: writes that land together are elected
// together, so two routers coming back at once keep their primary instead
// of handing the route to whichever reconnected first. Any other write
// commits at once.
func (w *world) lingerForBatch() {
	if w.batchTimeout <= 0 {
		return
	}

	timer := time.NewTimer(w.batchTimeout)
	defer timer.Stop()

	select {
	case <-timer.C:
	case <-w.full:
	}
}

// commitWrites commits every queued write in one transaction, then hands
// any writes queued meanwhile to a new leader so no caller waits on others'
// batches.
func (w *world) commitWrites() {
	w.writeMu.Lock()
	batch := w.writes
	w.writes = nil

	// A full signal for the writes taken here must not cut the next
	// batch's wait short.
	select {
	case <-w.full:
	default:
	}
	w.writeMu.Unlock()

	// Hand the commit on whatever happens below, or a panic would leave
	// committing set and every later write waiting for nothing.
	defer w.handOff()

	out, p, stack := w.commitBatch(batch)
	if p == nil {
		for _, nw := range batch {
			nw.done <- writeResult{snap: out}
		}

		return
	}

	worldCommitPanics.Add(1)
	log.Error().Interface("panic", p).Bytes("stack", stack).Int("batch", len(batch)).Msg("node write panicked")

	if len(batch) == 1 {
		batch[0].done <- writeResult{snap: out, panic: p}

		return
	}

	// One write's panic must not fail the others it was batched with:
	// commit each alone, so only the writes that panic again fail.
	for _, nw := range batch {
		out, p, _ := w.commitBatch([]*nodeWrite{nw})
		nw.done <- writeResult{snap: out, panic: p}
	}
}

// commitBatch commits batch's writes together, returning the panic one of
// them or a cell raised, with its stack, instead of letting it unwind the
// commit loop.
//
//nolint:nonamedreturns // the deferred recover sets the panic result
func (w *world) commitBatch(batch []*nodeWrite) (out *Snapshot, p any, stack []byte) {
	defer func() {
		if p = recover(); p != nil {
			stack = debug.Stack()
		}
	}()

	var checkOutage, changed bool

	snap, _ := w.g.Update(func(tx *graph.Tx) error {
		cur := graph.Peek(tx, w.nodes)
		e := &nodeEdit{MapEdit: cur.Edit(), users: graph.Peek(tx, w.users), dns: graph.Peek(tx, w.dns)}

		if idx := graph.Peek(tx, w.index); idx != nil {
			e.names = idx.byName
		}

		for _, nw := range batch {
			nw.fn(e)
		}

		next := e.Done()
		if next == cur {
			return nil
		}

		if w.batchTimeout > 0 {
			// Health can change without moving the primary, and policy
			// facts — tags, routes — can move elections without touching
			// anything the availability diff sees. One walk decides.
			checkOutage = electionInputChanged(cur, next)
		}

		graph.Set(tx, w.nodes, next)

		changed = true

		return nil
	})

	if changed {
		worldNodes.Set(float64(snap.Get(w.nodes).Len()))
		worldCommits.Inc()
	}

	worldBatchSize.Observe(float64(len(batch)))

	out = &Snapshot{s: snap, w: w}
	if checkOutage {
		w.storeOutage(out)
	}

	return out, nil, nil
}

// storeOutage records the outage state of snap, refusing a state computed
// from an older snapshot than the one already stored: whichever of two
// concurrent writers finished first, the newer snapshot's state wins.
func (w *world) storeOutage(snap *Snapshot) {
	// The state is a pure function of an immutable snapshot: compute it
	// outside the lock and hold the lock only to order the stores.
	rev, out := snap.Rev(), hasOutage(snap)

	w.outageMu.Lock()
	defer w.outageMu.Unlock()

	if rev < w.outageRev {
		return
	}

	w.outageRev = rev
	w.inOutage.Store(out)
	w.outageStores.Add(1)
}

// handOff ends the commit loop when no writes are queued, or starts the
// next commit for those that arrived during this one.
func (w *world) handOff() {
	w.writeMu.Lock()
	defer w.writeMu.Unlock()

	if len(w.writes) == 0 {
		w.committing = false

		return
	}

	go w.lead()
}

// lead runs the next commit, waiting first for writes to batch during an HA
// outage. Every commit goes through it, including those started for writes
// that arrived during the one before.
func (w *world) lead() {
	if w.inOutage.Load() {
		w.lingerForBatch()
	}

	w.commitWrites()
}

// UpdateNodeFunc modifies a node in place. It runs on a copy of the stored
// node, inside the writer, so it sees every write committed before it. If
// another write in its batch panics it runs again, alone, so it must only
// edit n and set what its caller reads afterwards, all of it on every run:
// the retry can see state the first run did not.
type UpdateNodeFunc func(n *types.Node)

// PutNode stores n, replacing any node with its ID. Its GivenName is made
// unique first. It returns the stored node.
func (w *world) PutNode(n types.Node) types.NodeView {
	snap := w.update(func(nodes *nodeEdit) {
		stored := n
		stored.GivenName = uniqueGivenName(nodes, n.ID, n.GivenName)
		nodes.Set(n.ID, &stored)
	})

	nv, _ := snap.GetNode(n.ID)

	return nv
}

// UpdateNode applies fn to the node with id and returns the result and
// whether the node exists.
func (w *world) UpdateNode(id types.NodeID, fn UpdateNodeFunc) (types.NodeView, bool) {
	_, after, ok := w.UpdateNodeDiff(id, fn)

	return after, ok
}

// UpdateNodeDiff is [world.UpdateNode] that also returns the node as it
// was before fn ran.
func (w *world) UpdateNodeDiff(id types.NodeID, fn UpdateNodeFunc) (types.NodeView, types.NodeView, bool) {
	pre := make(map[types.NodeID]types.NodeView, 1)
	snap, _ := w.updateNodes(map[types.NodeID]UpdateNodeFunc{id: fn}, nil, pre)
	after, ok := snap.GetNode(id)

	return pre[id], after, ok
}

// UpdateNodes applies every update in one commit, so no reader sees some of
// them without the others.
func (w *world) UpdateNodes(updates map[types.NodeID]UpdateNodeFunc) {
	w.updateNodes(updates, nil, nil)
}

// UpdateNodesIf is [world.UpdateNodes] applying each update only to a node
// that when accepts, checked in the writer: a write that an earlier check
// no longer warrants stores nothing, and costs no commit. It reports
// whether any update was applied.
func (w *world) UpdateNodesIf(updates map[types.NodeID]UpdateNodeFunc, when func(n *types.Node) bool) bool {
	_, applied := w.updateNodes(updates, when, nil)

	return applied
}

func (w *world) updateNodes(
	updates map[types.NodeID]UpdateNodeFunc,
	when func(n *types.Node) bool,
	pre map[types.NodeID]types.NodeView,
) (*Snapshot, bool) {
	if len(updates) == 0 {
		return w.snapshot(), false
	}

	var applied bool

	snap := w.update(func(nodes *nodeEdit) {
		applied = false

		for id, fn := range updates {
			cur, ok := nodes.Get(id)
			if !ok || when != nil && !when(cur) {
				continue
			}

			applied = true

			if pre != nil {
				pre[id] = cur.View()
			}

			next := cur.Clone()
			fn(next)
			// The callback owns a deep copy. Restore immutable route slices
			// only after it returns, when their values are unchanged.
			if len(cur.ApprovedRoutes) > 0 && slices.Equal(cur.ApprovedRoutes, next.ApprovedRoutes) {
				next.ApprovedRoutes = cur.ApprovedRoutes
			}

			if len(cur.AutoApprovedRoutes) > 0 && slices.Equal(cur.AutoApprovedRoutes, next.AutoApprovedRoutes) {
				next.AutoApprovedRoutes = cur.AutoApprovedRoutes
			}

			if cur.Hostinfo != nil && next.Hostinfo != nil && len(cur.Hostinfo.RoutableIPs) > 0 &&
				slices.Equal(cur.Hostinfo.RoutableIPs, next.Hostinfo.RoutableIPs) {
				next.Hostinfo.RoutableIPs = cur.Hostinfo.RoutableIPs
			}

			if next.GivenName != cur.GivenName {
				next.GivenName = uniqueGivenName(nodes, id, next.GivenName)
			}

			nodes.Set(id, next)
		}
	})

	return snap, applied
}

// DeleteNode removes the node with id.
func (w *world) DeleteNode(id types.NodeID) {
	w.update(func(nodes *nodeEdit) { nodes.Delete(id) })
}

// SetGivenName renames a node to exactly name, rejecting an invalid label
// and one another node holds (case-insensitively).
func (w *world) SetGivenName(id types.NodeID, name string) (types.NodeView, error) {
	var err error

	snap := w.update(func(nodes *nodeEdit) {
		err = nil

		cur, ok := nodes.Get(id)
		if !ok {
			err = ErrNodeNotFound

			return
		}

		if dnsname.ValidLabel(name) != nil {
			err = ErrGivenNameInvalid

			return
		}

		if nodes.nameTaken(id, name) {
			err = ErrGivenNameTaken

			return
		}

		next := cur.Clone()
		next.GivenName = name
		nodes.Set(id, next)
	})

	if err != nil {
		return types.NodeView{}, err
	}

	nv, _ := snap.GetNode(id)

	return nv, nil
}

// SetUsers replaces the user list and refreshes the user every node
// carries, so a renamed user is shown renamed.
func (w *world) SetUsers(users []types.User) error {
	// Most refreshes, one per registration, change nothing; they must not
	// queue behind a commit.
	before := w.g.Snapshot()
	if slices.Equal(before.Get(w.users), users) {
		return before.Get(w.policy).err
	}

	var changed bool

	snap, err := w.g.Update(func(tx *graph.Tx) error {
		changed = !slices.Equal(graph.Peek(tx, w.users), users)
		if !changed {
			return nil
		}

		was := make(map[uint]types.User)
		for _, u := range graph.Peek(tx, w.users) {
			was[u.ID] = u
		}

		graph.Set(tx, w.users, slices.Clone(users))

		cur := graph.Peek(tx, w.nodes)
		e := cur.Edit()

		// Only a changed user's nodes can hold a copy that differs; a
		// login changes one user, however many nodes others hold.
		var copies graph.Grouped[types.NodeID, *types.Node, uint]
		if idx := graph.Peek(tx, w.index); idx != nil {
			copies = idx.byUserCopy
		}

		current := make(map[uint]*types.User, len(users))
		for i := range users {
			current[users[i].ID] = &users[i]
		}

		changedUsers := make(map[uint]bool)

		for id, old := range was {
			next := current[id]
			changedUsers[id] = next == nil || !sameUserForNodes(old, *next)
		}

		for id := range current {
			if _, ok := was[id]; !ok {
				changedUsers[id] = true
			}
		}

		for uid, changed := range changedUsers {
			if !changed {
				continue
			}

			holders, _ := copies.Groups.Get(uid)
			for _, id := range holders {
				n, ok := e.Get(id)
				if !ok {
					continue
				}

				c := n.Clone()
				u := current[uid]
				edited := false

				if c.User != nil && c.User.ID == uid && (u == nil || !sameUserForNodes(*c.User, *u)) {
					c.User = u.Clone()
					edited = true
				}

				if c.AuthKey != nil && c.AuthKey.User != nil && c.AuthKey.User.ID == uid && (u == nil || !sameUserForNodes(*c.AuthKey.User, *u)) {
					c.AuthKey = c.AuthKey.Clone()

					c.AuthKey.User = u.Clone()
					if u == nil {
						c.AuthKey.UserID = nil
					}

					edited = true
				}

				if edited {
					e.Set(id, c)
				}
			}
		}

		if next := e.Done(); next != cur {
			graph.Set(tx, w.nodes, next)
		}

		return nil
	})
	if err != nil {
		return err
	}

	if changed {
		worldCommits.Inc()

		// A user change can move elections like a policy change can,
		// without any node availability changing.
		if w.batchTimeout > 0 {
			w.storeOutage(w.snapshot())
		}
	}

	return snap.Get(w.policy).err
}

// SetPolicy replaces the policy document and reports whether it differed
// from the live one. The commit is published only if check accepts it.
// It compiles incrementally, from the last good policy, while a caller
// checks a candidate compiled from scratch; the policy audit compares the
// two.
func (w *world) SetPolicy(src []byte, check func(*Snapshot) error) (bool, error) {
	var changed bool

	w.beforePolicyCommit()

	_, err := w.g.UpdateChecked(
		func(tx *graph.Tx) error {
			// Compared under the lock, so a document set twice at once is
			// compiled and published once.
			changed = !bytes.Equal(graph.Peek(tx, w.policySrc), src)
			if changed {
				graph.Set(tx, w.policySrc, src)
			} else {
				// UpdateChecked skips a no-op; explicit writes must still validate and persist.
				return check(&Snapshot{s: w.g.Snapshot(), w: w})
			}

			return nil
		},
		func(s *graph.Snapshot) error { return check(&Snapshot{s: s, w: w}) },
	)
	if err != nil || !changed {
		return false, err
	}

	worldCommits.Inc()

	// A policy change can move elections without any node availability
	// changing; the outage state follows it.
	if w.batchTimeout > 0 {
		w.storeOutage(w.snapshot())
	}

	return true, nil
}

// SetDERPMap replaces the DERP map.
func (w *world) SetDERPMap(dm *tailcfg.DERPMap) {
	var changed bool

	_, _ = w.g.Update(func(tx *graph.Tx) error {
		changed = !sameDERPMap(graph.Peek(tx, w.derpMap), dm)
		if changed {
			graph.Set(tx, w.derpMap, dm)
		}

		return nil
	})

	if changed {
		worldCommits.Inc()
	}
}

// sameDERPMap compares DERP maps by content; a fetch returns a new map
// even when nothing changed.
func sameDERPMap(a, b *tailcfg.DERPMap) bool {
	return reflect.DeepEqual(a, b)
}

// SetExtraRecords replaces the extra DNS records.
func (w *world) SetExtraRecords(records []tailcfg.DNSRecord) {
	var changed bool

	_, _ = w.g.Update(func(tx *graph.Tx) error {
		cur := graph.Peek(tx, w.dns)
		dns := cur.WithExtraRecords(records)

		changed = !cur.Equal(dns)
		if changed {
			graph.Set(tx, w.dns, dns)
		}

		return nil
	})

	if changed {
		worldCommits.Inc()
	}
}

// uniqueGivenName returns a DNS label for self based on base that no other
// node holds: base, base-1, base-2, … An empty base becomes
// [fallbackGivenName]. DNS is case-insensitive, so "Laptop" holds "laptop".
func uniqueGivenName(nodes *nodeEdit, self types.NodeID, base string) string {
	if base == "" {
		base = fallbackGivenName
	}

	candidate := base
	for i := 1; ; i++ {
		if !nodes.nameTaken(self, candidate) {
			return candidate
		}

		candidate = bumpedLabel(base, i)
	}
}

// hasOutage reports whether s has an HA outage: a prefix whose primary is
// unhealthy while no router for it is healthy. The primary keeps the
// route then, and the routers coming back should be elected together.
func hasOutage(s *Snapshot) bool {
	nodes := s.nodes()

	if len(s.s.Get(s.w.primaries).outages) > 0 {
		return true
	}

	// Via scopes count too: their candidates are not the global advertisers,
	// so a scope can lose every router while the global election stays
	// healthy through an untagged one.
	available := func(id types.NodeID) bool {
		n, ok := nodes.Get(id)

		return ok && servesRoutes(n) && !n.Unhealthy
	}

	return s.s.Get(s.w.primaries).via.HasOutage(available)
}

// electPrimaryRoutes elects every prefix from scratch, keeping prev's
// primaries where they still hold.
func electPrimaryRoutes(nodes *nodeMap, prev map[netip.Prefix]types.NodeID) map[netip.Prefix]types.NodeID {
	routes := make(map[netip.Prefix]types.NodeID)
	candidates := make(map[netip.Prefix][]types.NodeID)

	for id, n := range nodes.All() {
		for _, p := range electionRoutes(n) {
			candidates[p] = append(candidates[p], id)
		}
	}

	for p, ids := range candidates {
		slices.Sort(ids)

		if id, ok := electPrimary(nodes, views.SliceOf(ids), prev[p]); ok {
			routes[p] = id
		}
	}

	return routes
}

// electPrimary selects the oldest available control session, breaking ties by ID.
// Without an available router, the previous approver keeps the route, otherwise
// the lowest-ID healthy approver holds it until a router becomes available.
func electPrimary(nodes *nodeMap, candidates views.Slice[types.NodeID], cur types.NodeID) (types.NodeID, bool) {
	return electRouter(nodes, candidates, cur, true)
}

// Via grants use the lowest approving ID when no router is available;
// the global election instead retains its previous approving primary.
func electViaPrimary(nodes *nodeMap, candidates views.Slice[types.NodeID], _ types.NodeID) (types.NodeID, bool) {
	return electRouter(nodes, candidates, 0, false)
}

func electRouter(nodes *nodeMap, candidates views.Slice[types.NodeID], cur types.NodeID, retainPrevious bool) (types.NodeID, bool) {
	var oldest, firstHealthy, firstCandidate types.NodeID

	incumbent := false

	for _, id := range candidates.All() {
		n, ok := nodes.Get(id)
		if !ok {
			continue
		}

		if firstCandidate == 0 || id < firstCandidate {
			firstCandidate = id
		}

		incumbent = incumbent || id == cur
		if !n.Unhealthy && (firstHealthy == 0 || id < firstHealthy) {
			firstHealthy = id
		}

		if !servesRoutes(n) || n.Unhealthy {
			continue
		}

		if oldest == 0 {
			oldest = id
			continue
		}

		prev, _ := nodes.Get(oldest)
		if n.SessionStart.Before(prev.SessionStart) || n.SessionStart.Equal(prev.SessionStart) && id < oldest {
			oldest = id
		}
	}

	if oldest != 0 {
		return oldest, true
	}

	if !retainPrevious {
		return firstCandidate, firstCandidate != 0
	}

	if incumbent {
		return cur, true
	}

	return firstHealthy, firstHealthy != 0
}

// Snapshot is one consistent view of the control plane: nodes, users,
// compiled policy, peer visibility and primary routes all belong to the
// same commit. Everything rendered for a client should come from one
// Snapshot.
type Snapshot struct {
	s *graph.Snapshot
	w *world

	// uncached, when set, serves the filters instead of the cell's; see
	// [Snapshot.Uncached].
	uncached *policyv2.Filters
}

// Uncached returns s serving packet filters cut afresh from s's inputs,
// carrying nothing over from earlier commits and never filled from the
// served ones, and SSH policies read without filling the compile's caches:
// what an audit renders sessions against, since a filter carried over on
// routing's word would hide routing's mistake, and SSH routing reads what
// the compile prepared. Snapshots of the same filters share one such
// instance ([policyv2.Filters.Fresh]).
func (s *Snapshot) Uncached() *Snapshot {
	return &Snapshot{s: s.s, w: s.w, uncached: s.s.Get(s.w.filters).Fresh()}
}

// served returns the filters s serves.
func (s *Snapshot) served() *policyv2.Filters {
	if s.uncached != nil {
		return s.uncached
	}

	return s.s.Get(s.w.filters)
}

func (s *Snapshot) index() *nodeIndex { return s.s.Get(s.w.index) }

// Rev identifies the commit this snapshot shows.
func (s *Snapshot) Rev() uint64 { return s.s.Rev() }

// Time is when the commit this snapshot shows was made.
func (s *Snapshot) Time() time.Time { return s.s.Time() }

func (s *Snapshot) nodes() *nodeMap { return s.s.Get(s.w.nodes) }

// GetNode returns the node with id.
func (s *Snapshot) GetNode(id types.NodeID) (types.NodeView, bool) {
	n, ok := s.nodes().Get(id)
	if !ok {
		return types.NodeView{}, false
	}

	return n.View(), true
}

// GetNodeByNodeKey returns the node holding nodeKey.
func (s *Snapshot) GetNodeByNodeKey(nodeKey key.NodePublic) (types.NodeView, bool) {
	ids, _ := s.index().byNodeKey.Groups.Get(nodeKey)
	if len(ids) == 0 {
		return types.NodeView{}, false
	}

	// A machine re-registered under another user keeps its node key on
	// both nodes; the client speaks for the newer one, the highest ID.
	return s.GetNode(ids[len(ids)-1])
}

// GetNodesByMachineKeyAllUsers returns every node sharing machineKey,
// keyed by owning UserID; tagged nodes are under UserID(0).
func (s *Snapshot) GetNodesByMachineKeyAllUsers(machineKey key.MachinePublic) map[types.UserID]types.NodeView {
	ids, _ := s.index().byMachineKey.Groups.Get(machineKey)
	if len(ids) == 0 {
		return nil
	}

	out := make(map[types.UserID]types.NodeView, len(ids))

	for _, nv := range s.gather(ids) {
		// A tagged node may still record the user who created it; tags,
		// not that user, own it.
		owner := nv.TypedUserID()
		if nv.IsTagged() {
			owner = 0
		}

		out[owner] = nv
	}

	return out
}

// gather returns the views of ids, skipping any no longer stored.
func (s *Snapshot) gather(ids []types.NodeID) []types.NodeView {
	nodes := s.nodes()
	out := make([]types.NodeView, 0, len(ids))

	for _, id := range ids {
		if n, ok := nodes.Get(id); ok {
			out = append(out, n.View())
		}
	}

	return out
}

// ListNodes returns every node, sorted by ID.
func (s *Snapshot) ListNodes() views.Slice[types.NodeView] {
	return views.SliceOf(s.index().all.get())
}

// ListNodesByUser returns the user-owned nodes of uid.
func (s *Snapshot) ListNodesByUser(uid types.UserID) views.Slice[types.NodeView] {
	ids, _ := s.index().byUser.Groups.Get(uid)

	return views.SliceOf(s.gather(ids))
}

// ListPeerIDs returns the sorted IDs of the nodes id can see, as a copy
// the caller may keep and modify.
func (s *Snapshot) ListPeerIDs(id types.NodeID) []types.NodeID {
	return s.s.Get(s.w.peers).Peers(id)
}

// PeerView returns the sorted IDs of the nodes id can see, possibly
// including id itself: nodes that see the same nodes share one view. It
// is shared with the snapshot and must not be modified.
func (s *Snapshot) PeerView(id types.NodeID) []types.NodeID {
	return s.s.Get(s.w.peers).View(id)
}

// PeerReaders returns the nodes whose view holds id, as lists whose union
// they are; see [policyv2.PeerClasses.Readers]. Views are not symmetric.
func (s *Snapshot) PeerReaders(id types.NodeID) [][]types.NodeID {
	return s.s.Get(s.w.peers).Readers(id)
}

// PeerViews returns every distinct view; see [Snapshot.PeerView].
func (s *Snapshot) PeerViews() [][]types.NodeID { return s.s.Get(s.w.peers).Views() }

// ListPeers returns the nodes id can see, sorted by ID.
func (s *Snapshot) ListPeers(id types.NodeID) views.Slice[types.NodeView] {
	return views.SliceOf(s.gather(s.ListPeerIDs(id)))
}

// Policy returns the compiled policy. It serves SSH, node capabilities,
// tag owners, auto-approvers and DERP; packet filters, peers and routes
// come from [Snapshot.FilterForNode], [Snapshot.PeerView] and
// [Snapshot.RoutesForPeer].
func (s *Snapshot) Policy() policy.PolicyManager { return s.s.Get(s.w.policy).pm }

// FilterForNode returns the packet filter of node id: the policy's
// templates written for it in IP form, with membership from the postings.
// Callers share one slice, across commits that cannot change it. Under the
// policy audit, each served filter read is held to one cut afresh.
func (s *Snapshot) FilterForNode(id types.NodeID) ([]tailcfg.FilterRule, error) {
	rules, err := s.served().ForNode(id, s.ReceiverFacts(id))
	if err == nil && s.uncached == nil && s.w.auditing {
		s.auditServed(id, rules)
	}

	return rules, err
}

// auditServed holds the filter served to id, cut or carried over, to one
// cut afresh from the same inputs.
func (s *Snapshot) auditServed(id types.NodeID, served []tailcfg.FilterRule) {
	servedAuditRuns.Add(1)

	fresh := s.s.Get(s.w.filters).Fresh()

	want, err := fresh.ForNode(id, s.ReceiverFacts(id))
	if err == nil && !reflect.DeepEqual(want, served) {
		err = fmt.Errorf("%w: node %d at commit %d:\nserved %v\nafresh %v", errServedFilter, id, s.Rev(), served, want)
	}

	// In capability form, the filter must say what address form says once
	// each capability is the addresses of the nodes the receiver is sent
	// with it: itself and its peers, as the client looks them up.
	if err == nil && s.w.capSources {
		var ipForm []tailcfg.FilterRule

		ipForm, err = fresh.AddressForm(id)
		if err == nil {
			err = policyv2.AgreesWithAddressForm(served, ipForm, s.holdersFor(id))
		}

		if err != nil {
			err = fmt.Errorf("node %d at commit %d: %w", id, s.Rev(), err)
		}
	}

	// The check above assumes the client honours every capability it is
	// sent; which nodes are sent addresses instead is fallback.go's to
	// decide. Held here from the node itself, apart from that decision,
	// for the case that is unsafe: a node handling more than its own
	// addresses accepts ICMP from a capability source whatever the rule's
	// destinations.
	if err == nil && s.w.capSources {
		err = s.auditLocalNetsForm(id, served)
	}

	if err != nil {
		policyAuditFailures.Add(1)
		log.Error().Err(err).Msg("policy audit: filter")
	}
}

// auditLocalNetsForm reports a capability source in served when node id
// announces routes, approved or not, is an app connector or hosts a service
// IP.
func (s *Snapshot) auditLocalNetsForm(id types.NodeID, served []tailcfg.FilterRule) error {
	n, ok := s.GetNode(id)
	if !ok {
		return nil
	}

	_, serviceHost := s.NodeCaps(id)[nodecap.ServiceHost]
	hi := n.Hostinfo()
	wide := serviceHost || hi.Valid() && (hi.RoutableIPs().Len() > 0 || hi.AppConnector().EqualBool(true))

	if !wide {
		return nil
	}

	for _, r := range served {
		if slices.ContainsFunc(r.SrcIPs, func(src string) bool { return strings.HasPrefix(src, "cap:") }) {
			return fmt.Errorf("%w: node %d at commit %d handles more than its own addresses and was sent %v", errServedForm, id, s.Rev(), r.SrcIPs)
		}
	}

	return nil
}

var (
	errServedFilter = errors.New("served filter differs from one cut afresh")
	errServedForm   = errors.New("capability source sent to a node that must be sent addresses")
)

// holdersFor returns, for a capability, the addresses of the nodes viewer
// is sent holding it: itself and its peers.
func (s *Snapshot) holdersFor(viewer types.NodeID) func(nodecap.Cap) []netip.Addr {
	nodes := append([]types.NodeID{viewer}, s.PeerView(viewer)...)

	return func(c nodecap.Cap) []netip.Addr {
		var out []netip.Addr

		for _, id := range nodes {
			if _, ok := s.NodeCaps(id)[c]; !ok {
				continue
			}

			if n, ok := s.GetNode(id); ok {
				out = append(out, n.IPs()...)
			}
		}

		return out
	}
}

// SSHPolicy returns node's SSH policy from the compile. An uncached
// snapshot fills none of the compile's SSH caches.
func (s *Snapshot) SSHPolicy(baseURL string, node types.NodeView) (*tailcfg.SSHPolicy, error) {
	pm := s.Policy()
	if v2, ok := pm.(*policyv2.PolicyManager); ok && s.uncached != nil {
		return v2.SSHPolicyAfresh(baseURL, node)
	}

	return pm.SSHPolicy(baseURL, node)
}

// Filter returns the rules every node's filter is reduced from, before its
// own autogroup:self and via rules, with their matchers: for debugging and
// the policy's tests. Matchers are parsed from the rules on each call.
func (s *Snapshot) Filter() ([]tailcfg.FilterRule, []matcher.Match, error) {
	rules, err := s.served().Global()
	if err != nil {
		return nil, nil, err
	}

	return rules, matcher.MatchesFromFilterRules(rules), nil
}

// globalFilterFor returns pm's global filter expanded over the users and
// nodes of s, which pm must be compiled against: the served one for the
// compile s holds, else one built from s's membership, which carries over
// what pm's document shares with the one in force.
func (s *Snapshot) globalFilterFor(pm policy.PolicyManager) ([]tailcfg.FilterRule, error) {
	if pm == s.Policy() {
		return s.s.Get(s.w.filters).Global()
	}

	pmv2, ok := pm.(*policyv2.PolicyManager)
	if !ok {
		return nil, errNotV2Policy
	}

	holders := func(uid uint) []types.NodeID {
		ids, _ := s.index().byUserCopy.Groups.Get(uid)

		return ids
	}

	sel := policyv2.SelectorsFor(s.s.Get(s.w.selectors), pmv2)
	users := policyv2.NewUserSets(s.s.Get(s.w.userSets), sel, s.s.Get(s.w.policyUsers))
	roles := s.s.Get(s.w.roles).Update(users, s.nodes(), holders)

	return policyv2.NewFilters(policyv2.BuildTemplates(s.s.Get(s.w.templates), sel), s.s.Get(s.w.postings).Update(roles),
		s.s.Get(s.w.approvals), s.s.Get(s.w.policyNodes).list).Global()
}

var errNotV2Policy = errors.New("not a v2 policy")

// globalFilterOf is globalFilterFor for a candidate compiled against s's
// users and node list.
func (s *Snapshot) globalFilterOf(pm *policyv2.PolicyManager) ([]tailcfg.FilterRule, error) {
	return s.globalFilterFor(pm)
}

// PeerViewAndSideSet is [Snapshot.PeerView] with id's side set:
// everything that puts it on a side of a rule, which the routes its peers
// carry for it read. The classes are keyed by it, so one lookup gives both.
func (s *Snapshot) PeerViewAndSideSet(id types.NodeID) ([]types.NodeID, policyv2.RoleSet) {
	return s.s.Get(s.w.peers).ViewAndSideSet(id)
}

// PolicyErr is the error of the latest failed policy compile, or nil when
// the served policy is current.
func (s *Snapshot) PolicyErr() error { return s.s.Get(s.w.policy).err }

// policyInputs returns the users and nodes the policy compiles against,
// and the revision they last changed at.
func (s *Snapshot) policyInputs() ([]types.User, views.Slice[types.NodeView], uint64) {
	rev := max(graph.ChangedAt(s.s, s.w.policyUsers), graph.ChangedAt(s.s, s.w.policyNodes))

	return s.s.Get(s.w.policyUsers), s.s.Get(s.w.policyNodes).list, rev
}

// PolicySource returns the policy document. It is shared and must not be
// modified.
func (s *Snapshot) PolicySource() []byte { return s.s.Get(s.w.policySrc) }

// Users returns the user list.
func (s *Snapshot) Users() []types.User { return s.s.Get(s.w.users) }

// DERPMap returns the DERP map.
func (s *Snapshot) DERPMap() *tailcfg.DERPMap { return s.s.Get(s.w.effectiveDERP) }

// DNS returns the immutable DNS settings and records of this snapshot.
func (s *Snapshot) DNS() types.DNSView { return s.s.Get(s.w.dns) }

// PrimaryRoutes returns the prefix→primary assignment. It is shared and
// must not be modified.
func (s *Snapshot) PrimaryRoutes() map[netip.Prefix]types.NodeID {
	return s.s.Get(s.w.primaries).routes
}

// PrimaryRouteFor returns the primary advertiser of prefix.
func (s *Snapshot) PrimaryRouteFor(prefix netip.Prefix) (types.NodeID, bool) {
	id, ok := s.PrimaryRoutes()[prefix]

	return id, ok
}

// PrimaryRoutesForNode returns the prefixes id is primary for, sorted.
func (s *Snapshot) PrimaryRoutesForNode(id types.NodeID) []netip.Prefix {
	return slices.Clone(s.s.Get(s.w.primaries).byNode[id])
}

// PrimariesVersion is the primary routes of a snapshot, which a reader keeps
// to ask a later snapshot whose primaries moved. It holds one election's
// assignment, which the snapshots of that election share.
type PrimariesVersion struct {
	byNode map[types.NodeID][]netip.Prefix
}

// PrimariesVersion returns the version of the primary routes of s.
func (s *Snapshot) PrimariesVersion() PrimariesVersion {
	return PrimariesVersion{byNode: s.s.Get(s.w.primaries).byNode}
}

// PrimariesMovedSince returns the nodes among ids whose primary routes
// differ between v and s.
func (s *Snapshot) PrimariesMovedSince(v PrimariesVersion, ids []types.NodeID) []types.NodeID {
	byNode := s.s.Get(s.w.primaries).byNode

	var out []types.NodeID

	for _, id := range ids {
		if !sameNodePrimaries(v.byNode[id], byNode[id]) {
			out = append(out, id)
		}
	}

	return out
}

// sameNodePrimaries compares one node's primaries in two elections. A patched
// election shares every slice it did not move, so an identical slice is
// equal without walking its prefixes.
func sameNodePrimaries(a, b []netip.Prefix) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0] || slices.Equal(a, b))
}

// HANodes returns the prefixes with two or more online advertisers.
func (s *Snapshot) HANodes() map[netip.Prefix][]types.NodeID {
	out := make(map[netip.Prefix][]types.NodeID)

	nodes := s.nodes()
	for p, ids := range s.index().advertisers.Groups.All() {
		var online []types.NodeID

		unhealthy := false

		for _, id := range ids {
			n, ok := nodes.Get(id)
			if ok && servesRoutes(n) {
				online = append(online, id)
				unhealthy = unhealthy || n.Unhealthy
			}
		}

		if len(online) >= 2 || unhealthy {
			out[p] = online
		}
	}

	return out
}

// IsNodeHealthy reports the HA prober's view of id; unknown nodes are
// healthy.
func (s *Snapshot) IsNodeHealthy(id types.NodeID) bool {
	n, ok := s.s.Get(s.w.nodes).Get(id)

	return !ok || !n.Unhealthy
}

// PrimaryRoutesString renders the primary assignment for diagnostics.
func (s *Snapshot) PrimaryRoutesString() string {
	routes := s.PrimaryRoutes()

	var b strings.Builder
	for _, p := range slices.SortedFunc(maps.Keys(routes), netip.Prefix.Compare) {
		fmt.Fprintf(&b, "%s: %d\n", p, routes[p])
	}

	return b.String()
}

// ViaElection identifies the via elections [Snapshot.RoutesForPeer]
// steers by: equal pointers steer every viewer alike. Compare it only by
// identity.
func (s *Snapshot) ViaElection() *policyv2.ViaRoutes {
	return s.s.Get(s.w.primaries).via
}

// RoutesForPeer returns the routes peer carries in viewer's AllowedIPs: the
// primary routes it holds and its approved exit routes that the policy
// lets viewer use, adjusted by via grants. A viewer advertising a prefix
// the peer is primary for always sees it, so HA secondaries know the
// primary. viewer and peer are views of this snapshot.
func (s *Snapshot) RoutesForPeer(viewer, peer types.NodeView) []netip.Prefix {
	via := s.s.Get(s.w.primaries).via.ForPeer(viewer, peer)
	sides := s.s.Get(s.w.sides)
	primaries := s.PrimaryRoutesForNode(peer.ID())
	candidates := slices.Concat(primaries, peer.ExitRoutes())

	var reduced []netip.Prefix

	if len(via.Include) == 0 && len(via.Exclude) == 0 {
		reduced = sides.RouteAccess(viewer.ID(), candidates)
	} else {
		candidates = slices.DeleteFunc(candidates, func(p netip.Prefix) bool {
			return slices.Contains(via.Exclude, p)
		})
		reduced = sides.RouteAccess(viewer.ID(), candidates)

		// The via grant is the authorization. Where a regular grant also
		// covers the prefix, HA election decides: only the primary keeps it.
		for _, p := range via.Include {
			if slices.Contains(reduced, p) {
				continue
			}

			if slices.Contains(primaries, p) || !slices.Contains(via.UsePrimary, p) {
				reduced = append(reduced, p)
			}
		}
	}

	viewerSubnets := viewer.SubnetRoutes()
	for _, p := range primaries {
		if slices.Contains(viewerSubnets, p) && !slices.Contains(reduced, p) {
			reduced = append(reduced, p)
		}
	}

	// A single address inside the node ranges names a node, not a subnet: it
	// stays approved and in the router's own entry, but no viewer is served
	// it. Via inclusions skip the election, so the rule applies here, to
	// everything the viewer gets.
	if s.w.servesRoute != nil {
		reduced = slices.DeleteFunc(reduced, func(p netip.Prefix) bool { return !s.w.servesRoute(p) })
	}

	return reduced
}

// SelfRoutes returns the routes node carries in its own AllowedIPs: every
// route it serves, approved and announced, exits included, whatever the
// policy or the elections say.
func (s *Snapshot) SelfRoutes(node types.NodeView) []netip.Prefix { return node.AllApprovedRoutes() }

// Revisions report the commit at which a part of the world last changed,
// so a renderer can skip work whose inputs are unchanged.

// Change is what differs between two snapshots, for telling which map
// sessions an update can reach.
type Change struct {
	// Global is set when the change can reach any map: the DERP map or the
	// extra DNS records changed; commits coalesced past the node log; or a
	// delta below names every node or cannot be worked out (the filters
	// fail to expand, or the compile cannot tell whose SSH policy moved).
	// Across coalesced commits the deltas compare the two ends: a session
	// that rendered a snapshot in between is the reader's to wake.
	Global bool
	// Resync means the node edit history was exceeded; consumers must
	// check retained node state against the current snapshot.
	Resync bool
	// Nodes includes nodes changed back or deleted between snapshots
	// when commits coalesced: a session may have rendered them meanwhile.
	Nodes []types.NodeID
	// Primaries are the nodes that gained or lost a global or via-scoped route.
	Primaries []types.NodeID
	// PeerSets are the nodes whose set of peers differs.
	PeerSets []types.NodeID
	// Filters are the nodes whose packet filter or SSH policy can differ;
	// Caps those whose policy capabilities changed, which their viewers
	// render too.
	Filters, Caps []types.NodeID
	// RouteViewers are the nodes whose side set or side facts differ: the
	// routes any peer offers them can. Routers are the nodes whose subnet
	// routes' cover differs: the routes they offer any viewer can.
	// AllRouters is set when what every route reads moved (the rules, the
	// via plan, public members): every router's viewers render routes
	// again.
	RouteViewers, Routers []types.NodeID
	AllRouters            bool
}

// Since returns what changed from old to s. A nil old is everything.
//
// Each delta is read off the cell that serves what it routes: filters off
// the served filters, peers off the served classes, routes off the sides
// and the via plan, elections off the primaries. The compile is read only
// for what it still serves: SSH and node capabilities. A refused document
// needs nothing apart: what is served follows membership under the last
// good policy, and so does routing.
func (s *Snapshot) Since(old *Snapshot) Change {
	if old == nil {
		return Change{Global: true}
	}

	c := Change{
		Global: graph.ChangedAt(s.s, s.w.effectiveDERP) != graph.ChangedAt(old.s, old.w.effectiveDERP) ||
			s.DNSRev() != old.DNSRev(),
	}
	if s.Rev() > old.Rev()+1 {
		var complete bool

		// TODO(kradalby): overwake/since-coalesced-nodes: across coalesced
		// commits Nodes holds every node written between, also one written
		// back to what it was, whose viewers holding old's render have
		// nothing to receive (a node going offline and online again between
		// two routings). It predates the render log, which now wakes the
		// sessions that rendered in between; dropping such nodes takes
		// confirming nothing else leans on them. Counted by
		// TestSinceSoundOverAnyPair ("Nodes named across coalesced commits,
		// render unchanged").
		//
		// TODO(kradalby): overwake/since-node-log: past the node log's reach
		// (more commits between the two snapshots than it holds) the change
		// is Resync and Global: every session renders afresh. Safe; bounded by
		// the log. Fixing it takes diffing the two node maps when the log
		// cannot say. Not judged by TestSinceSoundOverAnyPair (a global change
		// answers everything).
		//
		// No upstream reference for either: headscale's own change routing.
		c.Nodes, complete = s.NodesTouchedSince(old.NodesVersion())
		c.Resync = !complete

		// The node log names nodes changed and changed back; every delta
		// below compares the two ends directly, which is exact for a
		// session holding old's render. One that rendered a snapshot in
		// between can hold what neither end has: the hub wakes those
		// itself, as it knows which sessions rendered since it last
		// routed.
		c.Global = c.Global || c.Resync
		if c.Global {
			return c
		}
	} else {
		c.Nodes = graph.Changes(old.nodes(), s.nodes())
	}

	if s.FiltersRev() != old.FiltersRev() {
		cur, was := s.s.Get(s.w.filters), old.s.Get(old.w.filters)

		// In capability mode a rule whose sources only address form reads
		// moved reaches the nodes served address form alone: the form a
		// read serves comes from the same facts, so a node sent
		// capabilities at both ends reads none of it.
		var (
			filters []types.NodeID
			all     bool
		)

		if s.w.capSources {
			filters, all = cur.ChangedFor(was, s.s.Get(s.w.receivers))
		} else {
			filters, all = cur.Changed(was)
		}

		// TODO(kradalby): overwake/since-filters-unheld,
		// overwake/since-expansion-failed: the filters say all when they
		// name every node, which is exact, but also when the old filters
		// hold nothing to compare across a document edit (compareFilters)
		// or the templates do not expand (routeFilters): every session is
		// woken then. Not judged by TestSinceSoundOverAnyPair. No upstream
		// reference: headscale's own change routing.
		if all {
			c.Global = true
		}

		c.Filters = filters
	}

	// A node whose facts moved is served its filter's other form, which
	// concerns it alone; the two ends' facts are compared directly.
	if s.w.capSources && graph.ChangedAt(s.s, s.w.receivers) != graph.ChangedAt(old.s, old.w.receivers) {
		c.Filters = append(c.Filters, s.s.Get(s.w.receivers).ChangedSince(old.s.Get(old.w.receivers))...)
	}

	if s.sshMoved(old) {
		next, _ := s.Policy().(*policyv2.PolicyManager)
		last, _ := old.Policy().(*policyv2.PolicyManager)

		// TODO(kradalby): overwake/since-ssh-unprepared: the compile says all
		// when no session has asked the last compile's SSH policy, so a
		// document edit or join under SSH rules wakes everyone; and it names
		// nodes whose SSH policy did not move (overwake/ssh-changed-nodes,
		// at PolicyManager.sshChangedNodes). SSH is the compile's to route
		// until it moves to the served cells. No upstream reference:
		// headscale's own change routing.
		ssh, all := next.SSHChangedNodes(last)
		if all {
			c.Global = true
		}

		c.Filters = append(c.Filters, ssh...)
	}

	if s.CapsRev() != old.CapsRev() {
		c.Caps = graph.Changes(old.caps(), s.caps())
	}

	if s.PrimariesRev() != old.PrimariesRev() {
		c.Primaries = changedKeys(old.s.Get(old.w.primaries).byNode, s.s.Get(s.w.primaries).byNode, sameNodePrimaries)

		was, now := old.s.Get(old.w.primaries).via, s.s.Get(s.w.primaries).via
		c.Primaries = append(c.Primaries, now.ChangedNodes(was)...)

		slices.Sort(c.Primaries)
		c.Primaries = slices.Compact(c.Primaries)
	}

	if s.PeersRev() != old.PeersRev() {
		c.PeerSets = s.s.Get(s.w.peers).Changed(old.s.Get(old.w.peers))
	}

	if s.SidesRev() != old.SidesRev() {
		sides, was := s.s.Get(s.w.sides), old.s.Get(old.w.sides)
		c.RouteViewers = sides.ViewersMovedSince(was)
		c.Routers = sides.RoutersMovedSince(was.RouteCover())
	}

	// TODO(kradalby): overwake/all-routers: any document edit that changes
	// the rules route access or via steering reads by content wakes every
	// router's viewers and renders every routed peer again for every viewer
	// (a port edit on a rule between two users with no routes). Safe: wakes
	// and renders that send nothing. Fixing it takes naming the routers
	// whose routes a moved rule can reach. Counted by
	// TestSinceSoundOverAnyPair ("AllRouters set, no route moved"). No
	// upstream reference: headscale's own route access.
	c.AllRouters = s.RouteRulesRev() != old.RouteRulesRev()

	return c
}

// sshMoved reports whether the compile, which serves SSH, recompiled from
// old to s with SSH rules at either end: without, every node is sent the
// same empty SSH policy.
func (s *Snapshot) sshMoved(old *Snapshot) bool {
	if s.PolicyRev() == old.PolicyRev() {
		return false
	}

	next, _ := s.Policy().(*policyv2.PolicyManager)
	last, _ := old.Policy().(*policyv2.PolicyManager)

	return next != last && (next.HasSSH() || last.HasSSH())
}

// changedKeys returns the keys whose value differs between a and b.
func changedKeys[K comparable, V any](a, b map[K]V, eq func(x, y V) bool) []K {
	var keys []K

	for k, v := range b {
		if old, ok := a[k]; !ok || !eq(old, v) {
			keys = append(keys, k)
		}
	}

	for k := range a {
		if _, ok := b[k]; !ok {
			keys = append(keys, k)
		}
	}

	return keys
}

// RoutedNodes returns the nodes serving an approved route, sorted. It is
// shared and must not be modified.
func (s *Snapshot) RoutedNodes() []types.NodeID {
	ids, _ := s.index().routed.Groups.Get(true)

	return ids
}

// CapsVersion is the policy's node capabilities in a snapshot, which a
// reader keeps to ask a later snapshot whose caps changed.
type CapsVersion struct{ m *capsMap }

// CapsVersion returns the node capabilities of s.
func (s *Snapshot) CapsVersion() CapsVersion { return CapsVersion{m: s.caps()} }

// CapsChangedSince returns the nodes whose capabilities as rendered differ
// between v and s.
func (s *Snapshot) CapsChangedSince(v CapsVersion) []types.NodeID {
	return graph.Changes(v.m, s.caps())
}

// caps returns every node's capabilities as peers and the node itself are
// sent them: the policy's, with the stamps in capability mode.
func (s *Snapshot) caps() *capsMap {
	if s.w.capSources {
		return s.s.Get(s.w.renderCaps).m
	}

	return s.s.Get(s.w.nodeCaps)
}

// NodeCaps returns node id's capabilities as it and its peers are sent
// them. The map is shared and must not be modified.
func (s *Snapshot) NodeCaps(id types.NodeID) tailcfg.NodeCapMap {
	c, _ := s.caps().Get(id)

	return c
}

// AddressHolders are the nodes holding each address of a snapshot.
type AddressHolders struct {
	m *graph.Map[netip.Addr, []types.NodeID]
}

// Valid reports whether h holds anything: false in address mode, where no
// session reads it.
func (h AddressHolders) Valid() bool { return h.m != nil }

// Of returns the nodes holding addr. The slice is shared.
func (h AddressHolders) Of(addr netip.Addr) []types.NodeID {
	ids, _ := h.m.Get(addr)

	return ids
}

// AddressHolders returns the nodes holding each address, in capability
// mode only.
func (s *Snapshot) AddressHolders() AddressHolders {
	if !s.w.capSources {
		return AddressHolders{}
	}

	return AddressHolders{m: s.s.Get(s.w.holders).m}
}

// CapabilitySources reports whether s names filter sources by capability.
func (s *Snapshot) CapabilitySources() bool { return s.w.capSources }

// FilterChunks reports whether filters may go as named chunks
// (policy.filter_chunks); each session asks [policyv2.FilterDelivery].
func (s *Snapshot) FilterChunks() bool { return s.w.filterChunks }

// Stamps returns the source capabilities node id holds; none without
// capability sources.
func (s *Snapshot) Stamps(id types.NodeID) policyv2.Stamps {
	if !s.w.capSources {
		return nil
	}

	st, _ := s.s.Get(s.w.stamps).m.Get(id)

	return st
}

// ReceiverFacts returns what decides the form of node id's filter beyond
// the policy; nothing without capability sources.
func (s *Snapshot) ReceiverFacts(id types.NodeID) policyv2.ReceiverFacts {
	if !s.w.capSources {
		return policyv2.ReceiverFacts{}
	}

	return s.s.Get(s.w.receivers).Of(id)
}

// FallbackCensus counts what the served filters' fallbacks send as
// addresses, see [policyv2.FallbackCensus]; nothing in address mode.
func (s *Snapshot) FallbackCensus() (policyv2.FallbackCensus, error) {
	if !s.w.capSources {
		return policyv2.FallbackCensus{}, nil
	}

	return s.s.Get(s.w.filters).Census(s.s.Get(s.w.receivers))
}

// NodesVersion identifies the nodes of a snapshot, which a reader keeps to
// ask a later snapshot what changed since. It holds no nodes, so a reader
// that keeps one for long, such as an idle peer class, pins nothing.
type NodesVersion struct{ m *nodeMap }

// NodesVersion returns the version of the nodes of s.
func (s *Snapshot) NodesVersion() NodesVersion { return NodesVersion{m: s.nodes().Cursor()} }

// NodesTouchedSince returns the nodes the writes from v to s touched,
// possibly with repeats and nodes that changed back, while v is within
// the nodes' edit log; otherwise false, and the caller should not compare
// every node when a smaller set covers what it needs.
func (s *Snapshot) NodesTouchedSince(v NodesVersion) ([]types.NodeID, bool) {
	return s.nodes().ChangedSince(v.m)
}

// CapsRev is the revision of the latest change to any node's capabilities
// as rendered: a peer's render reads its node and its caps only.
func (s *Snapshot) CapsRev() uint64 {
	if s.w.capSources {
		return graph.ChangedAt(s.s, s.w.renderCaps)
	}

	return graph.ChangedAt(s.s, s.w.nodeCaps)
}

// SidesRev is the revision of the latest change to the side sets, side
// facts or routes' cover the routes a viewer is sent read.
func (s *Snapshot) SidesRev() uint64 { return graph.ChangedAt(s.s, s.w.sides) }

// RouteRulesRev is the revision of the latest change to what every route
// reads beyond the viewer, the peer and its routes' cover.
func (s *Snapshot) RouteRulesRev() uint64 { return graph.ChangedAt(s.s, s.w.routeRules) }

// RouteCover is the cover of every routed prefix in s, which a reader keeps
// to ask a later snapshot whose routes' cover moved.
func (s *Snapshot) RouteCover() policyv2.RouteCover { return s.s.Get(s.w.sides).RouteCover() }

// RoutersMovedSince returns the routers whose routes' cover differs since
// c: the routes they offer a viewer can, though neither changed.
func (s *Snapshot) RoutersMovedSince(c policyv2.RouteCover) []types.NodeID {
	return s.s.Get(s.w.sides).RoutersMovedSince(c)
}

// ViewerFacts identifies what route access reads of viewer id beyond its
// side set.
func (s *Snapshot) ViewerFacts(id types.NodeID) policyv2.ViewerFacts {
	return s.s.Get(s.w.sides).ViewerFacts(id)
}

// FiltersRev is the revision of the latest change to what packet filters
// are expanded from.
func (s *Snapshot) FiltersRev() uint64 { return graph.ChangedAt(s.s, s.w.filters) }

// PolicyRev is the revision of the latest policy compile.
func (s *Snapshot) PolicyRev() uint64 { return graph.ChangedAt(s.s, s.w.policy) }

// PeersRev is the revision of the latest change to peer visibility.
func (s *Snapshot) PeersRev() uint64 { return graph.ChangedAt(s.s, s.w.peers) }

// PrimariesRev is the revision of the latest global or via-scoped route change.
func (s *Snapshot) PrimariesRev() uint64 { return graph.ChangedAt(s.s, s.w.primaries) }

// DNSRev is the revision of the latest extra DNS records change.
func (s *Snapshot) DNSRev() uint64 { return graph.ChangedAt(s.s, s.w.dns) }

func bumpedLabel(base string, n int) string {
	suffix := "-" + strconv.Itoa(n)

	return strings.TrimRight(base[:min(len(base), util.LabelHostnameLength-len(suffix))], "-") + suffix
}

// uniqueGivenNames repairs duplicate stored labels in memory, keeping the lowest ID.
func uniqueGivenNames(nodes types.Nodes) map[types.NodeID]*types.Node {
	ordered := slices.SortedFunc(slices.Values(nodes), func(a, b *types.Node) int { return cmp.Compare(a.ID, b.ID) })
	out := make(map[types.NodeID]*types.Node, len(nodes))
	taken := make(map[string]bool, len(nodes))

	var duplicates types.Nodes

	for _, n := range ordered {
		name := strings.ToLower(n.GivenName)
		if name != "" && taken[name] {
			duplicates = append(duplicates, n)
			continue
		}

		out[n.ID] = n

		if name != "" {
			taken[name] = true
		}
	}

	for _, prior := range duplicates {
		n := prior.Clone()

		candidate := n.GivenName
		for i := 1; taken[strings.ToLower(candidate)]; i++ {
			candidate = bumpedLabel(n.GivenName, i)
		}

		n.GivenName = candidate
		taken[strings.ToLower(candidate)] = true
		out[n.ID] = n
		log.Warn().Uint64("node.id", n.ID.Uint64()).Str("old.given_name", prior.GivenName).Str("new.given_name", n.GivenName).Msg("renaming duplicate node name in memory")
	}

	return out
}

func servesRoutes(n *types.Node) bool {
	return n.Online() && !n.IsExpired()
}

func reservedLabel(dns types.DNSView, label string) bool {
	if dns.BaseDomain() == "" {
		return false
	}

	name := strings.TrimSuffix(label+"."+dns.BaseDomain(), ".")
	for _, r := range dns.ExtraRecords().All() {
		if strings.EqualFold(strings.TrimSuffix(r.Name, "."), name) {
			return true
		}
	}

	return false
}

// RouterSession reports the session order and availability from this snapshot.
func (s *Snapshot) RouterSession(id types.NodeID) (time.Time, bool) {
	n, ok := s.nodes().Get(id)
	if !ok {
		return time.Time{}, false
	}

	return n.SessionStart, servesRoutes(n) && !n.Unhealthy
}

// SameWorld reports whether both snapshots belong to the same graph.
func (s *Snapshot) SameWorld(other *Snapshot) bool { return s != nil && other != nil && s.w == other.w }

// censusWorld is the world of the latest server, whose fallbacks the
// census metrics report.
var censusWorld atomic.Pointer[world]

// censusCollector reports, per reason, the nodes whose filter goes as
// addresses and the rules with a source that does, read off the latest
// snapshot at each scrape; and the filters and rules cut so, as counters.
type censusCollector struct {
	receivers, rules, cuts, ruleCuts, deliveries *prometheus.Desc
}

func newCensusCollector() censusCollector {
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", name), help, []string{"reason"}, nil)
	}

	return censusCollector{
		receivers: desc("policy_address_form_receivers",
			"Nodes by why their whole packet filter is sent with every source as addresses; capability counts those sent capability sources."),
		rules: desc("policy_address_form_rules",
			"Rules of filters sent capability sources, by why a source of theirs is sent as addresses; an autogroup:self rule counts once per owner; capability counts rules with none."),
		cuts:     desc("policy_address_form_filters_cut_total", "Packet filters cut with every source as addresses, by reason."),
		ruleCuts: desc("policy_address_form_rules_cut_total", "Rules cut with a source as addresses into filters otherwise sent capabilities, by reason."),
		deliveries: prometheus.NewDesc(prometheus.BuildFQName(prometheusNamespace, "", "policy_filter_deliveries_total"),
			"Decisions of how a map session's packet filter is sent, by outcome: chunks, or the whole filter and why; a session decides at its first render and again each time its node's client reports itself otherwise.",
			[]string{"delivery"}, nil),
	}
}

func (c censusCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.receivers, c.rules, c.cuts, c.ruleCuts, c.deliveries} {
		ch <- d
	}
}

func (c censusCollector) Collect(ch chan<- prometheus.Metric) {
	filters, rules := policyv2.AddressFormCounts()
	for reason, n := range filters {
		ch <- prometheus.MustNewConstMetric(c.cuts, prometheus.CounterValue, float64(n), reason)
	}

	for reason, n := range rules {
		ch <- prometheus.MustNewConstMetric(c.ruleCuts, prometheus.CounterValue, float64(n), reason)
	}

	for delivery, n := range policyv2.FilterDeliveryCounts() {
		ch <- prometheus.MustNewConstMetric(c.deliveries, prometheus.CounterValue, float64(n), delivery)
	}

	w := censusWorld.Load()
	if w == nil {
		return
	}

	census, err := w.snapshot().FallbackCensus()
	if err != nil {
		return
	}

	receivers, perRule := census.Labelled()
	for reason, n := range receivers {
		ch <- prometheus.MustNewConstMetric(c.receivers, prometheus.GaugeValue, float64(n), reason)
	}

	for reason, n := range perRule {
		ch <- prometheus.MustNewConstMetric(c.rules, prometheus.GaugeValue, float64(n), reason)
	}
}

func init() { prometheus.MustRegister(newCensusCollector()) }
