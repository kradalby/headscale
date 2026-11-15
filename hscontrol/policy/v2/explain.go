package v2

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"
)

var (
	errAccessUnavailable   = errors.New("policy or node unavailable")
	errAccessSourceObject  = errors.New("policy is not an object")
	errAccessSourcePointer = errors.New("invalid source pointer or offset")
	errAccessSourceOffset  = errors.New("invalid source offset")
)

// AccessQuery selects one directional IP tuple. Destination is the receiving
// node, including a candidate router when DestinationIP is outside the tailnet.
type AccessQuery struct {
	Source, Destination     types.NodeView
	SourceIP, DestinationIP netip.Addr
	Protocol                uint8
	Port                    uint16
	SSHUser                 string
	EvidenceOffset          int
	OmitEvidence            bool
}

type AccessRuleReference struct {
	Pointer          string            `json:"pointer"`
	Digest           string            `json:"digest"`
	Excerpt          string            `json:"excerpt"`
	Comments         string            `json:"comments"`
	Line             int               `json:"line"`
	Truncated        bool              `json:"truncated"`
	SourceMatch      *AccessMembership `json:"sourceMatch,omitempty"`
	DestinationMatch *AccessMembership `json:"destinationMatch,omitempty"`
}

// AccessMembership is one original-selector witness, resolved by the policy engine.
// It does not claim that this was the only matching selector.
type AccessMembership struct {
	Selector  string `json:"selector"`
	Kind      string `json:"kind"`
	Address   string `json:"address"`
	NodeID    string `json:"nodeId"`
	Ownership string `json:"ownership"`
	UserID    string `json:"userId"`
}

const accessEvidenceLimit = 10

type AccessCapability struct {
	Name  string                `json:"name"`
	Rules []AccessRuleReference `json:"rules"`
}

type AccessRuleCheck struct {
	Rule   AccessRuleReference `json:"rule"`
	Reason string              `json:"reason"`
}

type AccessExplanation struct {
	Checks            []AccessRuleCheck     `json:"checks"`
	ChecksTotal       int                   `json:"checksTotal"`
	ChecksOmitted     int                   `json:"checksOmitted"`
	RulesTotal        int                   `json:"rulesTotal"`
	RulesOmitted      int                   `json:"rulesOmitted"`
	EvidenceOffset    int                   `json:"evidenceOffset"`
	EvidenceNext      *int                  `json:"evidenceNext"`
	SSHRulesTotal     int                   `json:"sshRulesTotal"`
	CapabilitiesTotal int                   `json:"capabilitiesTotal"`
	SSHRules          []AccessRuleReference `json:"sshRules"`
	Packet            string                `json:"packet"`
	SSH               string                `json:"ssh"`
	Reason            string                `json:"reason"`
	Diagnostic        string                `json:"diagnostic"`
	Rules             []AccessRuleReference `json:"rules"`
	Capabilities      []AccessCapability    `json:"capabilities"`
}

type AccessRange struct {
	Source       string   `json:"source"`
	Destination  string   `json:"destination"`
	Protocols    []int    `json:"protocols"`
	First        uint16   `json:"first"`
	Last         uint16   `json:"last"`
	Capabilities []string `json:"capabilities"`
}

// ExplainAccess reads the effective destination filter, then independently
// attributes its matching contributions to original policy rules. Raw must be
// the exact policy source belonging to this compile.
func (pm *PolicyManager) ExplainAccess(q AccessQuery, raw []byte) AccessExplanation {
	out := AccessExplanation{Packet: "unavailable", SSH: "unavailable", Rules: []AccessRuleReference{}, Capabilities: []AccessCapability{}}
	if pm == nil || !q.Destination.Valid() || !q.SourceIP.IsValid() || !q.DestinationIP.IsValid() {
		out.Diagnostic = "policy, node or address unavailable"
		return out
	}

	if !q.Source.Valid() || !slices.Contains(q.Source.IPs(), q.SourceIP) || q.SourceIP.Is4() != q.DestinationIP.Is4() {
		out.Diagnostic = "source address is not owned by source node or address families differ"
		return out
	}

	effective, err := pm.FilterForNode(q.Destination)
	if err != nil {
		out.Diagnostic = err.Error()
		return out
	}

	allowed := accessMatches(effective, q)
	out.Packet = "denied"

	out.Reason = "no matching allow"
	if allowed {
		out.Packet = "allowed"
		out.Reason = "matching allow"
	}

	if q.SSHUser != "" {
		out.SSH = pm.explainSSH(q)
	}

	if pm.pol == nil || (pm.pol.Grants == nil && pm.pol.ACLs == nil) {
		out.Reason = "default policy"
		if q.SSHUser == "" || pm.pol == nil {
			return out
		}
	}

	if q.OmitEvidence {
		return out
	}

	out.EvidenceOffset = max(0, q.EvidenceOffset)

	if !bytes.Equal(raw, pm.src) {
		out.Diagnostic = "source does not match compiled policy; attribution unavailable"
		return out
	}

	refs, err := accessSourceReferences(raw)
	if err != nil {
		out.Diagnostic = "source attribution unavailable: " + err.Error()
		return out
	}

	if q.SSHUser != "" && pm.pol != nil {
		for i, rule := range pm.pol.SSHs {
			single := *pm.pol
			single.SSHs = []SSH{rule}

			ssh, err := single.compileSSHPolicy("", pm.users, q.Destination, pm.nodes)
			if err != nil {
				out.Diagnostic = "SSH attribution unavailable: " + err.Error()
				break
			}

			accept, _ := reachability(accessSSHSourceRules(ssh, q.SourceIP), q.SSHUser)
			if accept {
				if ref, ok := refs["/ssh/"+strconv.Itoa(i)]; ok {
					out.SSHRulesTotal++
					if accessOnPage(out.SSHRulesTotal, out.EvidenceOffset) {
						out.SSHRules = append(out.SSHRules, pm.accessReferenceMembership(ref, q, true))
					}
				}
			}
		}
	}

	if out.Reason == "default policy" {
		return accessEvidenceNext(out)
	}

	return pm.explainPacketContributions(q, refs, allowed, out)
}

func (pm *PolicyManager) explainPacketContributions(q AccessQuery, refs map[string]AccessRuleReference, allowed bool, out AccessExplanation) AccessExplanation {
	pointers := make([]string, 0, len(pm.grantResults))
	for i := range pm.pol.Grants {
		pointers = append(pointers, "/grants/"+strconv.Itoa(i))
	}

	for i, acl := range pm.pol.ACLs {
		for range aclToGrants(acl) {
			pointers = append(pointers, "/acls/"+strconv.Itoa(i))
		}
	}

	if len(pointers) != len(pm.grantResults) {
		out.Diagnostic = "compiled contribution alignment unavailable"
		return out
	}

	checks := map[string]int{}
	traced := false
	seen := map[string]bool{}
	caps := map[string][]AccessRuleReference{}
	capSeen := map[string]map[string]bool{}

	var dsts policyutil.DstCache

	for i, result := range pm.grantResults {
		if result.cg == nil {
			if _, ok := checks[pointers[i]]; !ok {
				checks[pointers[i]] = 0
			}

			continue
		}

		cg := result.cg
		rules := filterRulesForNode([]compiledGrant{*cg}, q.Destination, pm.userNodeIdx)
		rules = dsts.Reduce(q.Destination, rules)

		ref, ok := refs[pointers[i]]
		if !ok {
			out.Diagnostic = "original rule unavailable"
			out.Rules = nil

			return out
		}

		stage := accessMismatchStage(rules, q)
		if stage > checks[ref.Pointer] {
			checks[ref.Pointer] = stage
		} else if _, ok := checks[ref.Pointer]; !ok {
			checks[ref.Pointer] = stage
		}

		if accessMatches(rules, q) {
			traced = true

			if !seen[ref.Pointer] {
				seen[ref.Pointer] = true

				out.RulesTotal++
				if accessOnPage(out.RulesTotal, out.EvidenceOffset) {
					out.Rules = append(out.Rules, pm.accessReferenceMembership(ref, q, true))
				}
			}
		}

		for _, name := range accessCaps(rules, q.SourceIP, q.DestinationIP) {
			if capSeen[name] == nil {
				capSeen[name] = map[string]bool{}
			}

			if !capSeen[name][ref.Pointer] {
				capSeen[name][ref.Pointer] = true

				out.CapabilitiesTotal++
				if accessOnPage(out.CapabilitiesTotal, out.EvidenceOffset) {
					caps[name] = append(caps[name], pm.accessReferenceMembership(ref, q, true))
				}
			}
		}
	}

	if !allowed {
		reasons := []string{"no effective destination or router contribution (selectors may resolve to no nodes)", "source address does not match this rule's resolved sources", "destination address does not match this rule's effective destinations", "selected protocol does not match", "selected port is outside the allowed ranges", "matching packet allow"}

		visited := map[string]bool{}
		for _, pointer := range pointers {
			if visited[pointer] {
				continue
			}

			visited[pointer] = true

			out.ChecksTotal++
			if !accessOnPage(out.ChecksTotal, out.EvidenceOffset) {
				continue
			}

			out.Checks = append(out.Checks, AccessRuleCheck{Rule: pm.accessReferenceMembership(refs[pointer], q, false), Reason: reasons[checks[pointer]]})
		}
	}

	if traced != allowed {
		out.Rules = nil
		out.Diagnostic = "effective verdict and contribution trace disagree; attribution unavailable"
	}

	for name, rules := range caps {
		out.Capabilities = append(out.Capabilities, AccessCapability{Name: accessPreview(name, 256), Rules: rules})
	}

	slices.SortFunc(out.Capabilities, func(a, b AccessCapability) int { return strings.Compare(a.Name, b.Name) })

	return accessEvidenceNext(out)
}

func (pm *PolicyManager) explainSSH(q AccessQuery) string {
	policy, err := pm.SSHPolicy("", q.Destination)
	if err != nil {
		return "unavailable"
	}

	if policy != nil {
		for _, rule := range accessSSHSourceRules(policy, q.SourceIP) {
			if !sshUserMapAllows(rule.SSHUsers, q.SSHUser) || rule.Action == nil {
				continue
			}

			if rule.Action.Reject {
				return "denied"
			}

			if rule.Action.HoldAndDelegate != "" {
				return "conditional"
			}

			if rule.Action.Accept {
				return "allowed"
			}
		}
	}

	return "denied"
}

// accessSSHSourceRules keeps compiled order while selecting the exact principal.
func accessSSHSourceRules(policy *tailcfg.SSHPolicy, source netip.Addr) []*tailcfg.SSHRule {
	var rules []*tailcfg.SSHRule
	if policy == nil {
		return rules
	}

	for _, rule := range policy.Rules {
		if rule == nil {
			continue
		}

		for _, principal := range rule.Principals {
			if principal == nil {
				continue
			}

			address, err := netip.ParseAddr(principal.NodeIP)
			if err == nil && address == source {
				rules = append(rules, rule)
				break
			}
		}
	}

	return rules
}

func accessContains(text string, ip netip.Addr) bool {
	set, err := util.ParseIPSet(text, nil)
	return err == nil && set != nil && set.Contains(ip)
}

func accessSourceMatches(rule tailcfg.FilterRule, ip netip.Addr) bool {
	return slices.ContainsFunc(rule.SrcIPs, func(s string) bool { return accessContains(s, ip) })
}

func accessMatches(rules []tailcfg.FilterRule, q AccessQuery) bool {
	for _, rule := range rules {
		if !accessSourceMatches(rule, q.SourceIP) {
			continue
		}
		// A missing IPProto means TCP, UDP and ICMP, as specified by tailcfg.
		if len(rule.IPProto) == 0 {
			if q.Protocol != 6 && q.Protocol != 17 && q.Protocol != 1 && q.Protocol != 58 {
				continue
			}
		} else if !slices.Contains(rule.IPProto, int(q.Protocol)) {
			continue
		}

		for _, dst := range rule.DstPorts {
			if accessContains(dst.IP, q.DestinationIP) && (q.Protocol != 6 && q.Protocol != 17 && q.Protocol != 132 || q.Port >= dst.Ports.First && q.Port <= dst.Ports.Last) {
				return true
			}
		}
	}

	return false
}

func accessCaps(rules []tailcfg.FilterRule, src, dst netip.Addr) []string {
	var names []string

	for _, rule := range rules {
		if !accessSourceMatches(rule, src) {
			continue
		}

		for _, grant := range rule.CapGrant {
			if !slices.ContainsFunc(grant.Dsts, func(p netip.Prefix) bool { return p.Contains(dst) }) {
				continue
			}

			for name := range grant.CapMap {
				names = append(names, string(name))
			}

			for _, name := range grant.Caps {
				names = append(names, string(name))
			}
		}
	}

	slices.Sort(names)

	return slices.Compact(names)
}

// SummarizeAccess returns bounded-size filter ranges for one pair, never an
// all-pairs materialization or an expansion of a port range into individual ports.
func (pm *PolicyManager) SummarizeAccess(source, destination types.NodeView) ([]AccessRange, error) {
	out := []AccessRange{}
	if pm == nil || !source.Valid() || !destination.Valid() {
		return out, errAccessUnavailable
	}

	rules, err := pm.FilterForNode(destination)
	if err != nil {
		return nil, err
	}

	for _, src := range source.IPs() {
		for _, dst := range destination.IPs() {
			if src.Is4() != dst.Is4() {
				continue
			}

			for _, rule := range rules {
				if !accessSourceMatches(rule, src) {
					continue
				}

				for _, r := range rule.DstPorts {
					if accessContains(r.IP, dst) {
						protocols := slices.Clone(rule.IPProto)
						if len(protocols) == 0 {
							protocols = []int{1, 6, 17, 58}
						}

						out = append(out, AccessRange{Source: src.String(), Destination: dst.String(), Protocols: protocols, First: r.Ports.First, Last: r.Ports.Last})
					}
				}

				if caps := accessCaps([]tailcfg.FilterRule{rule}, src, dst); len(caps) > 0 {
					out = append(out, AccessRange{Source: src.String(), Destination: dst.String(), Capabilities: caps})
				}
			}
		}
	}

	return out, nil
}

func accessSourceReferences(raw []byte) (map[string]AccessRuleReference, error) {
	ast, err := hujson.Parse(bytes.Clone(raw))
	if err != nil {
		return nil, err
	}

	obj, ok := ast.Value.(*hujson.Object)
	if !ok {
		return nil, errAccessSourceObject
	}

	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	out := map[string]AccessRuleReference{}

	for _, member := range obj.Members {
		name, ok := member.Name.Value.(hujson.Literal)
		if !ok {
			continue
		}

		key := name.String()
		if key != "grants" && key != "acls" && key != "ssh" {
			continue
		}

		array, ok := member.Value.Value.(*hujson.Array)
		if !ok {
			continue
		}

		for i, v := range array.Elements {
			pointer := "/" + key + "/" + strconv.Itoa(i)
			out[pointer] = AccessRuleReference{Pointer: pointer, Digest: digest, Excerpt: accessPreview(string(raw[v.StartOffset:v.EndOffset]), 512), Comments: accessPreview(strings.TrimSpace(string(v.BeforeExtra)+string(v.AfterExtra)), 256), Truncated: v.EndOffset-v.StartOffset > 512 || len(v.BeforeExtra)+len(v.AfterExtra) > 256, Line: 1 + bytes.Count(raw[:v.StartOffset], []byte("\n"))}
		}
	}

	return out, nil
}

// accessMismatchStage identifies the furthest matching condition. It reports
// evidence about each contribution, never a unique edit that would allow it.
func accessMismatchStage(rules []tailcfg.FilterRule, q AccessQuery) int {
	stage := 0

	for _, rule := range rules {
		if len(rule.DstPorts) == 0 {
			continue
		}

		stage = max(stage, 1)

		if !accessSourceMatches(rule, q.SourceIP) {
			continue
		}

		stage = max(stage, 2)

		for _, dst := range rule.DstPorts {
			if !accessContains(dst.IP, q.DestinationIP) {
				continue
			}

			stage = max(stage, 3)

			if len(rule.IPProto) == 0 {
				if q.Protocol != 6 && q.Protocol != 17 && q.Protocol != 1 && q.Protocol != 58 {
					continue
				}
			} else if !slices.Contains(rule.IPProto, int(q.Protocol)) {
				continue
			}

			stage = max(stage, 4)
			if q.Protocol != 6 && q.Protocol != 17 && q.Protocol != 132 || q.Port >= dst.Ports.First && q.Port <= dst.Ports.Last {
				stage = 5
			}
		}
	}

	return stage
}

func accessOnPage(total, offset int) bool {
	return total > offset && total <= offset+accessEvidenceLimit
}

func accessEvidenceNext(out AccessExplanation) AccessExplanation {
	out.RulesOmitted = out.RulesTotal - len(out.Rules)

	out.ChecksOmitted = out.ChecksTotal - len(out.Checks)
	if max(out.RulesTotal, out.ChecksTotal, out.SSHRulesTotal, out.CapabilitiesTotal) > out.EvidenceOffset+accessEvidenceLimit {
		next := out.EvidenceOffset + accessEvidenceLimit
		out.EvidenceNext = &next
	}

	return out
}

func accessPreview(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	// Preserve UTF-8 so JSON encoding cannot change the source chunk boundary.
	for limit > 0 && limit < len(s) && s[limit]&0xc0 == 0x80 {
		limit--
	}

	return s[:limit]
}

func (pm *PolicyManager) accessReferenceMembership(ref AccessRuleReference, q AccessQuery, contributionMatched bool) AccessRuleReference {
	var src, dst []Alias

	kind, index, _ := strings.Cut(strings.TrimPrefix(ref.Pointer, "/"), "/")
	i, _ := strconv.Atoi(index)

	switch kind {
	case "grants":
		src, dst = pm.pol.Grants[i].Sources, pm.pol.Grants[i].Destinations
	case "acls":
		src = pm.pol.ACLs[i].Sources
		for _, d := range pm.pol.ACLs[i].Destinations {
			dst = append(dst, d.Alias)
		}
	case "ssh":
		src, dst = pm.pol.SSHs[i].Sources, pm.pol.SSHs[i].Destinations
	}

	witness := func(aliases []Alias, ip netip.Addr, n types.NodeView, destination bool) *AccessMembership {
		for _, alias := range aliases {
			var matched bool
			if ag, ok := alias.(*AutoGroup); ok && ag.Is(AutoGroupSelf) {
				// Self is contextual: witness only a compiled match between same-user owned nodes.
				matched = destination && contributionMatched && sshNodesShareUser(q.Source, q.Destination) && q.Destination.HasIP(ip)
			} else {
				resolved, err := alias.Resolve(pm.pol, pm.users, pm.nodes)
				matched = err == nil && resolved != nil && resolved.Contains(ip)
			}

			if matched {
				owner := "user"
				if n.IsTagged() {
					owner = "tags"
				}

				return &AccessMembership{Selector: accessPreview(alias.String(), 256), Kind: strings.TrimPrefix(fmt.Sprintf("%T", alias), "*v2."), Address: ip.String(), NodeID: fmt.Sprint(n.ID()), Ownership: owner, UserID: fmt.Sprint(n.TailscaleUserID())}
			}
		}

		return nil
	}
	ref.SourceMatch = witness(src, q.SourceIP, q.Source, false)
	ref.DestinationMatch = witness(dst, q.DestinationIP, q.Destination, true)

	return ref
}

// AccessSourceChunk returns bounded original rule text, including surrounding comments.
// The caller must bind raw to the requested snapshot revision.
func AccessSourceChunk(raw []byte, pointer string, offset int) (string, int, *int, error) {
	ast, err := hujson.Parse(bytes.Clone(raw))
	if err != nil {
		return "", 0, nil, err
	}

	v := ast.Find(pointer)
	if v == nil || offset < 0 {
		return "", 0, nil, errAccessSourcePointer
	}

	text := string(v.BeforeExtra) + string(raw[v.StartOffset:v.EndOffset]) + string(v.AfterExtra)
	if offset > len(text) || offset < len(text) && text[offset]&0xc0 == 0x80 {
		return "", 0, nil, errAccessSourceOffset
	}

	chunk := accessPreview(text[offset:], 8192)

	var next *int

	if offset+len(chunk) < len(text) {
		n := offset + len(chunk)
		next = &n
	}

	return chunk, len(text), next, nil
}
