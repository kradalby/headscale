package mapper

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

const (
	nextDNSDoHPrefix     = "https://dns.nextdns.io"
	debugMapResponsePerm = 0o755
)

var debugDumpMapResponsePath = envknob.String("HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH")

func generateDNSConfig(
	dns types.DNSView,
	node types.NodeView,
	capMap tailcfg.NodeCapMap,
) *tailcfg.DNSConfig {
	dnsConfig := dns.AsStruct()
	if dnsConfig == nil {
		return nil
	}

	profile := nextDNSProfileFromCapMap(capMap)
	if profile != "" {
		applyNextDNSProfile(dnsConfig.Resolvers, profile)
		applyNextDNSProfile(dnsConfig.FallbackResolvers, profile)

		for suffix, rs := range dnsConfig.Routes {
			applyNextDNSProfile(rs, profile)
			dnsConfig.Routes[suffix] = rs
		}
	}

	if _, suppressMetadata := capMap[policyv2.NextDNSAttrNoInfo]; !suppressMetadata {
		addNextDNSMetadata(dnsConfig.Resolvers, node)
		addNextDNSMetadata(dnsConfig.FallbackResolvers, node)

		for suffix, rs := range dnsConfig.Routes {
			addNextDNSMetadata(rs, node)
			dnsConfig.Routes[suffix] = rs
		}
	}

	if domain, ok := node.CertDomain(dns); ok {
		dnsConfig.CertDomains = []string{domain}
	}

	// An exit node refuses to proxy these names. Without this, where its OS
	// resolver reaches MagicDNS, a client allowed only to use the exit node can
	// read its view of the tailnet through it. Two gaps are deliberate. Without
	// MagicDNS, base_domain can be a public domain whose names clients ask the
	// exit node for, so node names stay readable. Reverse lookups stay open, as
	// on Tailscale SaaS.
	if dnsConfig.Proxied && dns.BaseDomain() != "" {
		dnsConfig.ExitNodeFilteredSet = []string{"." + strings.ToLower(dns.BaseDomain())}
	}

	return dnsConfig
}

// nextDNSProfileFromCapMap returns the policy-selected
// `nextdns:<profile>` value on the node, or the empty string when none
// is set or the cap is malformed. The reserved
// `nextdns:no-device-info` string is not a profile — it controls
// metadata appending and is handled separately.
//
// The profile pick is deterministic across reloads: cap keys are
// gathered, sorted, and the first valid profile wins. Map iteration
// order in Go is randomised, so taking the literal first match would
// cause the chosen profile to flip between reloads when a node has
// multiple `nextdns:` caps. The profile string is also validated
// against [policyv2.NextDNSProfileRE] so a crafted cap cannot inject path or
// query characters into the resolver URL.
func nextDNSProfileFromCapMap(capMap tailcfg.NodeCapMap) string {
	if len(capMap) == 0 {
		return ""
	}

	candidates := make([]string, 0, len(capMap))

	for attr := range capMap {
		if attr == policyv2.NextDNSAttrNoInfo {
			continue
		}

		profile, ok := strings.CutPrefix(string(attr), policyv2.NextDNSAttrPrefix)
		if !ok || profile == "" {
			continue
		}

		// Skipped in silence: the policy warns once when it loads, and this
		// check guards the URL splice.
		if !policyv2.NextDNSProfileRE.MatchString(profile) {
			continue
		}

		candidates = append(candidates, profile)
	}

	if len(candidates) == 0 {
		return ""
	}

	slices.Sort(candidates)

	return candidates[0]
}

// nextDNSDoHHost matches a NextDNS DoH resolver address. The check is
// anchored on the host segment so a typo-squatted operator-configured
// resolver such as `https://dns.nextdns.io.attacker.example/x` does
// not slip through.
func nextDNSDoHHost(addr string) bool {
	return addr == nextDNSDoHPrefix ||
		strings.HasPrefix(addr, nextDNSDoHPrefix+"/") ||
		strings.HasPrefix(addr, nextDNSDoHPrefix+"?")
}

// applyNextDNSProfile rewrites every NextDNS DoH resolver to point at
// the given profile, dropping any existing profile path or query. Per
// the Tailscale spec the per-node profile overrides the global value,
// so the rewrite is unconditional rather than additive.
func applyNextDNSProfile(resolvers []*dnstype.Resolver, profile string) {
	for _, resolver := range resolvers {
		if !nextDNSDoHHost(resolver.Addr) {
			continue
		}

		resolver.Addr = nextDNSDoHPrefix + "/" + profile
	}
}

// addNextDNSMetadata appends device metadata as a query string to
// every NextDNS DoH resolver. Existing query parameters on the
// resolver address are preserved by parsing the URL and merging into
// its [url.URL.RawQuery] rather than concatenating with `?`.
func addNextDNSMetadata(resolvers []*dnstype.Resolver, node types.NodeView) {
	for _, resolver := range resolvers {
		if !nextDNSDoHHost(resolver.Addr) {
			continue
		}

		u, err := url.Parse(resolver.Addr)
		if err != nil {
			continue
		}

		q := u.Query()
		q.Set("device_id", string(node.ID().StableID()))
		q.Set("device_name", node.Hostname())

		// Guard Hostinfo().Valid() before dereferencing OS(): a node loaded
		// from a legacy NULL host_info row has a nil Hostinfo, and OS() would
		// panic. Mirrors the .Valid() guard in RequestTags/TailNode.
		if node.Hostinfo().Valid() {
			q.Set("device_model", node.Hostinfo().OS())
		}

		if ips := node.IPs(); len(ips) > 0 {
			q.Set("device_ip", ips[0].String())
		}

		u.RawQuery = q.Encode()
		resolver.Addr = u.String()
	}
}

// fullMapResponse returns a [tailcfg.MapResponse] for the given node.
//
//nolint:unused
func writeDebugMapResponse(resp *tailcfg.MapResponse, nodeID types.NodeID) {
	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		panic(err)
	}

	perms := fs.FileMode(debugMapResponsePerm)
	mPath := path.Join(debugDumpMapResponsePath, fmt.Sprintf("%d", nodeID))

	err = os.MkdirAll(mPath, perms)
	if err != nil {
		panic(err)
	}

	now := time.Now().Format("2006-01-02T15-04-05.999999999")

	mapResponsePath := path.Join(
		mPath,
		now+".json",
	)

	log.Trace().Msgf("writing MapResponse to %s", mapResponsePath)

	err = os.WriteFile(mapResponsePath, body, perms)
	if err != nil {
		panic(err)
	}
}

// DebugMapResponses returns the map responses dumped to
// HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH, or nil when dumping is off.
func DebugMapResponses() (map[types.NodeID][]tailcfg.MapResponse, error) {
	if debugDumpMapResponsePath == "" {
		return nil, nil //nolint:nilnil // intentional: no data when debug path not set
	}

	return ReadMapResponsesFromDirectory(debugDumpMapResponsePath)
}

func ReadMapResponsesFromDirectory(dir string) (map[types.NodeID][]tailcfg.MapResponse, error) {
	nodes, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	result := make(map[types.NodeID][]tailcfg.MapResponse)

	for _, node := range nodes {
		if !node.IsDir() {
			continue
		}

		nodeIDu, err := strconv.ParseUint(node.Name(), 10, 64)
		if err != nil {
			log.Error().Err(err).Msgf("parsing node ID from dir %s", node.Name())
			continue
		}

		nodeID := types.NodeID(nodeIDu)

		files, err := os.ReadDir(path.Join(dir, node.Name()))
		if err != nil {
			log.Error().Err(err).Msgf("reading dir %s", node.Name())
			continue
		}

		slices.SortStableFunc(files, func(a, b fs.DirEntry) int {
			return strings.Compare(a.Name(), b.Name())
		})

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}

			body, err := os.ReadFile(path.Join(dir, node.Name(), file.Name()))
			if err != nil {
				log.Error().Err(err).Msgf("reading file %s", file.Name())
				continue
			}

			var resp tailcfg.MapResponse

			err = json.Unmarshal(body, &resp)
			if err != nil {
				log.Error().Err(err).Msgf("unmarshalling file %s", file.Name())
				continue
			}

			result[nodeID] = append(result[nodeID], resp)
		}
	}

	return result, nil
}
