package state

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"time"

	hsdb "github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/tailcfg"
)

// DebugOverviewInfo represents the state overview information in a structured format.
type DebugOverviewInfo struct {
	Nodes struct {
		Total     int `json:"total"`
		Online    int `json:"online"`
		Expired   int `json:"expired"`
		Ephemeral int `json:"ephemeral"`
	} `json:"nodes"`
	Users      map[string]int `json:"users"` // username -> node count
	TotalUsers int            `json:"total_users"`
	Policy     struct {
		Mode string `json:"mode"`
		Path string `json:"path,omitempty"`
	} `json:"policy"`
	DERP struct {
		Configured bool `json:"configured"`
		Regions    int  `json:"regions"`
	} `json:"derp"`
	PrimaryRoutes int `json:"primary_routes"`
}

// DebugDERPInfo represents DERP map information in a structured format.
type DebugDERPInfo struct {
	Configured   bool                                      `json:"configured"`
	TotalRegions int                                       `json:"total_regions"`
	Regions      map[tailcfg.DERPRegionID]*DebugDERPRegion `json:"regions,omitempty"`
}

// DebugDERPRegion represents a single DERP region.
type DebugDERPRegion struct {
	RegionID   tailcfg.DERPRegionID `json:"region_id"`
	RegionName string               `json:"region_name"`
	Nodes      []*DebugDERPNode     `json:"nodes"`
}

// DebugDERPNode represents a single DERP node.
type DebugDERPNode struct {
	Name     string `json:"name"`
	HostName string `json:"hostname"`
	DERPPort int    `json:"derp_port"`
	STUNPort int    `json:"stun_port,omitempty"`
}

// DebugStringInfo wraps a debug string for JSON serialization.
type DebugStringInfo struct {
	Content string `json:"content"`
}

// DebugOverview returns a comprehensive overview of the current state for debugging.
func (s *State) DebugOverview() string {
	info := s.DebugOverviewJSON()

	var sb strings.Builder

	sb.WriteString("=== Headscale State Overview ===\n\n")

	// Node statistics
	fmt.Fprintf(&sb, "Nodes: %d total\n", info.Nodes.Total)
	fmt.Fprintf(&sb, "  - Online: %d\n", info.Nodes.Online)
	fmt.Fprintf(&sb, "  - Expired: %d\n", info.Nodes.Expired)
	fmt.Fprintf(&sb, "  - Ephemeral: %d\n", info.Nodes.Ephemeral)
	sb.WriteString("\n")

	// User statistics
	fmt.Fprintf(&sb, "Users: %d total\n", info.TotalUsers)

	for userName, nodeCount := range info.Users {
		fmt.Fprintf(&sb, "  - %s: %d nodes\n", userName, nodeCount)
	}

	sb.WriteString("\n")

	// Policy information
	sb.WriteString("Policy:\n")
	fmt.Fprintf(&sb, "  - Mode: %s\n", info.Policy.Mode)

	if info.Policy.Mode == string(types.PolicyModeFile) {
		fmt.Fprintf(&sb, "  - Path: %s\n", info.Policy.Path)
	}

	sb.WriteString("\n")

	// DERP information
	if info.DERP.Configured {
		fmt.Fprintf(&sb, "DERP: %d regions configured\n", info.DERP.Regions)
	} else {
		sb.WriteString("DERP: not configured\n")
	}

	sb.WriteString("\n")

	// Route information
	fmt.Fprintf(&sb, "Primary Routes: %d active\n", info.PrimaryRoutes)
	sb.WriteString("\n")

	// Registration cache
	sb.WriteString("Registration Cache: active\n")
	sb.WriteString("\n")

	return sb.String()
}

// DebugNodeStore returns debug information about the in-memory nodes, their
// peers and primary routes, all from one snapshot.
func (s *State) DebugNodeStore() string {
	snap := s.Snapshot()
	nodes := snap.ListNodes()

	var sb strings.Builder

	sb.WriteString("=== Node State Debug Information ===\n\n")

	fmt.Fprintf(&sb, "Snapshot Revision: %d\n", snap.Rev())
	fmt.Fprintf(&sb, "Total Nodes: %d\n\n", nodes.Len())

	// Internal UserID tracking, not display owner: tagged nodes are listed
	// under no user.
	byUser := make(map[types.UserID][]types.NodeView)

	for _, nv := range nodes.All() {
		if !nv.IsTagged() {
			byUser[nv.TypedUserID()] = append(byUser[nv.TypedUserID()], nv)
		}
	}

	fmt.Fprintf(&sb, "Users with Nodes: %d\n", len(byUser))
	sb.WriteString("Nodes by Internal User ID:\n")

	for _, uid := range slices.Sorted(maps.Keys(byUser)) {
		userName := "unknown"
		if u := byUser[uid][0].User(); u.Valid() {
			userName = u.Name()
		}

		fmt.Fprintf(&sb, "  - User %d (%s): %d nodes\n", uid, userName, len(byUser[uid]))
	}

	sb.WriteString("\n")

	sb.WriteString("Peer Relationships:\n")

	totalPeers := 0

	for _, nv := range nodes.All() {
		peerCount := len(snap.ListPeerIDs(nv.ID()))
		totalPeers += peerCount

		fmt.Fprintf(&sb, "  - Node %d (%s): %d peers\n", nv.ID(), nv.Hostname(), peerCount)
	}

	if nodes.Len() > 0 {
		fmt.Fprintf(&sb, "  - Average peers per node: %.1f\n", float64(totalPeers)/float64(nodes.Len()))
	}

	sb.WriteString("\n")

	sb.WriteString("Primary Routes:\n")
	sb.WriteString(snap.PrimaryRoutesString())
	sb.WriteString("\n")

	return sb.String()
}

// DebugDERPMap returns debug information about the DERP map configuration.
func (s *State) DebugDERPMap() string {
	derpMap := s.Snapshot().DERPMap()
	if derpMap == nil {
		return "DERP Map: not configured\n"
	}

	var sb strings.Builder

	sb.WriteString("=== DERP Map Configuration ===\n\n")

	fmt.Fprintf(&sb, "Total Regions: %d\n\n", len(derpMap.Regions))

	for regionID, region := range derpMap.Regions {
		fmt.Fprintf(&sb, "Region %d: %s\n", regionID, region.RegionName)
		fmt.Fprintf(&sb, "  - Nodes: %d\n", len(region.Nodes))

		for _, node := range region.Nodes {
			fmt.Fprintf(&sb, "    - %s (%s:%d)\n",
				node.Name, node.HostName, node.DERPPort)

			if node.STUNPort != 0 {
				fmt.Fprintf(&sb, "      STUN: %d\n", node.STUNPort)
			}
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

// DebugSSHPolicies returns debug information about SSH policies for all nodes.
func (s *State) DebugSSHPolicies() map[string]*tailcfg.SSHPolicy {
	snap := s.Snapshot()
	nodes := snap.ListNodes()

	sshPolicies := make(map[string]*tailcfg.SSHPolicy)

	for _, node := range nodes.All() {
		if !node.Valid() {
			continue
		}

		pol, err := snap.Policy().SSHPolicy(s.cfg.ServerURL, node)
		if err != nil {
			// Store the error information
			continue
		}

		key := fmt.Sprintf("id:%d hostname:%s givenname:%s",
			node.ID(), node.Hostname(), node.GivenName())
		sshPolicies[key] = pol
	}

	return sshPolicies
}

// DebugRegistrationCache returns debug information about the registration cache.
func (s *State) DebugRegistrationCache() map[string]any {
	return map[string]any{
		"type":        "expirable-lru",
		"expiration":  registerCacheExpiration.String(),
		"max_entries": defaultRegisterCacheMaxEntries,
		"current_len": s.authCache.Len(),
		"status":      "active",
	}
}

// DebugConfig returns debug information about the current configuration.
func (s *State) DebugConfig() *types.Config {
	return s.cfg
}

// DebugPolicy returns the current policy data as a string.
func (s *State) DebugPolicy() (string, error) {
	switch s.cfg.Policy.Mode {
	case types.PolicyModeDB:
		p, err := s.GetPolicy()
		if err != nil {
			return "", err
		}

		return p.Data, nil
	case types.PolicyModeFile:
		pol, err := hsdb.PolicyBytes(s.db.DB, s.cfg)
		if err != nil {
			return "", err
		}

		return string(pol), nil
	default:
		return "", fmt.Errorf("%w: %s", ErrUnsupportedPolicyMode, s.cfg.Policy.Mode)
	}
}

// DebugFilter returns the current filter rules and matchers.
func (s *State) DebugFilter() ([]tailcfg.FilterRule, error) {
	filter, _ := s.Filter()
	return filter, nil
}

// DebugRoutes returns the current primary routes information as a
// structured object built from one [Snapshot].
func (s *State) DebugRoutes() types.DebugRoutes {
	snap := s.Snapshot()

	debug := types.DebugRoutes{
		AvailableRoutes: make(map[types.NodeID][]netip.Prefix),
		PrimaryRoutes:   make(map[string]types.NodeID),
	}

	for _, nv := range snap.ListNodes().All() {
		if !nv.Valid() {
			continue
		}

		online, known := nv.IsOnline().GetOk()
		if !known || !online {
			continue
		}

		approved := nv.AllApprovedRoutes()
		if len(approved) == 0 {
			continue
		}

		slices.SortFunc(approved, netip.Prefix.Compare)
		debug.AvailableRoutes[nv.ID()] = approved
	}

	for prefix, id := range snap.PrimaryRoutes() {
		debug.PrimaryRoutes[prefix.String()] = id
	}

	var unhealthy []types.NodeID

	for _, nv := range snap.ListNodes().All() {
		if !nv.Valid() {
			continue
		}

		if !snap.IsNodeHealthy(nv.ID()) {
			unhealthy = append(unhealthy, nv.ID())
		}
	}

	if len(unhealthy) > 0 {
		slices.Sort(unhealthy)
		debug.UnhealthyNodes = unhealthy
	}

	return debug
}

// DebugRoutesString returns the current primary routes information as a string.
func (s *State) DebugRoutesString() string {
	return s.PrimaryRoutesString()
}

// DebugPolicyManager returns the policy manager debug string.
func (s *State) DebugPolicyManager() string {
	return s.PolicyDebugString()
}

// PolicyDebugString returns a debug representation of the current policy.
func (s *State) PolicyDebugString() string {
	return s.Snapshot().Policy().DebugString()
}

// DebugOverviewJSON returns a structured overview of the current state for debugging.
func (s *State) DebugOverviewJSON() DebugOverviewInfo {
	snap := s.Snapshot()
	allNodes := snap.ListNodes()
	users, _ := s.ListAllUsers()

	info := DebugOverviewInfo{
		Users:      make(map[string]int),
		TotalUsers: len(users),
	}

	// Node statistics
	info.Nodes.Total = allNodes.Len()
	now := time.Now()

	for _, node := range allNodes.All() {
		if node.Valid() {
			userName := node.Owner().Name()
			info.Users[userName]++

			if node.IsOnline().Valid() && node.IsOnline().Get() {
				info.Nodes.Online++
			}

			if node.Expiry().Valid() && node.Expiry().Get().Before(now) {
				info.Nodes.Expired++
			}

			if node.AuthKey().Valid() && node.AuthKey().Ephemeral() {
				info.Nodes.Ephemeral++
			}
		}
	}

	// Policy information
	info.Policy.Mode = string(s.cfg.Policy.Mode)
	if s.cfg.Policy.Mode == types.PolicyModeFile {
		info.Policy.Path = s.cfg.Policy.Path
	}

	derpMap := snap.DERPMap()
	if derpMap != nil {
		info.DERP.Configured = true
		info.DERP.Regions = len(derpMap.Regions)
	} else {
		info.DERP.Configured = false
		info.DERP.Regions = 0
	}

	// Route information
	info.PrimaryRoutes = len(snap.PrimaryRoutes())

	return info
}

// DebugDERPJSON returns structured debug information about the DERP map configuration.
func (s *State) DebugDERPJSON() DebugDERPInfo {
	derpMap := s.Snapshot().DERPMap()

	info := DebugDERPInfo{
		Configured: derpMap != nil,
		Regions:    make(map[tailcfg.DERPRegionID]*DebugDERPRegion),
	}

	if derpMap == nil {
		return info
	}

	info.TotalRegions = len(derpMap.Regions)

	for regionID, region := range derpMap.Regions {
		debugRegion := &DebugDERPRegion{
			RegionID:   regionID,
			RegionName: region.RegionName,
			Nodes:      make([]*DebugDERPNode, 0, len(region.Nodes)),
		}

		for _, node := range region.Nodes {
			debugNode := &DebugDERPNode{
				Name:     node.Name,
				HostName: node.HostName,
				DERPPort: node.DERPPort,
				STUNPort: node.STUNPort,
			}
			debugRegion.Nodes = append(debugRegion.Nodes, debugNode)
		}

		info.Regions[regionID] = debugRegion
	}

	return info
}

// DebugNodeStoreJSON returns a copy of every node in the current snapshot.
func (s *State) DebugNodeStoreJSON() map[types.NodeID]types.Node {
	nodes := s.Snapshot().ListNodes()

	out := make(map[types.NodeID]types.Node, nodes.Len())
	for _, nv := range nodes.All() {
		out[nv.ID()] = *nv.AsStruct()
	}

	return out
}

// DebugPolicyManagerJSON returns structured debug information about the policy manager.
func (s *State) DebugPolicyManagerJSON() DebugStringInfo {
	return DebugStringInfo{
		Content: s.Snapshot().Policy().DebugString(),
	}
}
