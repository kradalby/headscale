package policymodel

import (
	"encoding/json"
	"fmt"
	"slices"

	"pgregory.net/rapid"
)

// Defect is one way a policy is invalid on purpose. Each is a single
// addition to a valid document, so a refusal is about that addition.
type Defect uint8

const (
	// DefectReservedAttr grants, through nodeAttrs, a capability in the
	// namespace of source capabilities.
	DefectReservedAttr Defect = iota
	// DefectReservedApp names such a capability in an app grant.
	DefectReservedApp
	// DefectSelfSource names autogroup:self as a source.
	DefectSelfSource
	// DefectUndefinedTag names a tag tagOwners does not define.
	DefectUndefinedTag
	// DefectUndefinedGroup names a group groups does not define.
	DefectUndefinedGroup
	// DefectUndefinedHost names a host hosts does not define.
	DefectUndefinedHost
	// DefectDefaultRouteDst names 0.0.0.0/0 as a grant destination.
	DefectDefaultRouteDst
	// DefectAppToInternet grants an app capability to autogroup:internet.
	DefectAppToInternet
	// DefectPortsOnICMP gives a port to a protocol without ports.
	DefectPortsOnICMP
	// DefectFunnelAttr grants funnel, which headscale cannot serve.
	DefectFunnelAttr
	// DefectViaInACL routes an ACL via a tag, which only grants can.
	DefectViaInACL
	// DefectSSHWildcardSource names * as an SSH source.
	DefectSSHWildcardSource
	// DefectTagStartsWithDigit defines a tag not starting with a letter.
	DefectTagStartsWithDigit
	// DefectGrantWithoutIPOrApp grants neither ip nor app.
	DefectGrantWithoutIPOrApp
)

const numDefects = int(DefectGrantWithoutIPOrApp) + 1

func (d Defect) String() string {
	return [...]string{
		"reserved-attr", "reserved-app", "self-source", "undefined-tag", "undefined-group", "undefined-host",
		"default-route-dst", "app-to-internet", "ports-on-icmp", "funnel-attr", "via-in-acl",
		"ssh-wildcard-source", "tag-starts-with-digit", "grant-without-ip-or-app",
	}[d]
}

// ReservedCaps are spellings of capabilities in the reserved namespace:
// with and without the scheme, the bare prefix, and one with a path.
var ReservedCaps = []string{
	"https://headscale.net/cap/src/group:a",
	"headscale.net/cap/src/tag:a",
	"https://headscale.net/cap/src/",
	"headscale.net/cap/src/owner:1/x",
}

// InvalidPolicy is a valid policy with one defect added at position At of
// the list the defect goes in.
type InvalidPolicy struct {
	Policy Policy
	Defect Defect
	// Spelling indexes ReservedCaps, for the reserved defects.
	Spelling int
	At       int
}

// InvalidPolicies draws documents headscale must refuse.
func InvalidPolicies() *rapid.Generator[InvalidPolicy] { return invalidPolicies }

var invalidPolicies = rapid.Custom(func(t *rapid.T) InvalidPolicy {
	return InvalidPolicy{
		Policy:   policies.Draw(t, "policy"),
		Defect:   Defect(index(t, numDefects, "defect")), //nolint:gosec // a few defects
		Spelling: index(t, len(ReservedCaps), "spelling"),
		At:       rapid.IntRange(0, 4).Draw(t, "at"),
	}
})

// HuJSON writes the policy with its defect.
func (iv InvalidPolicy) HuJSON() []byte {
	var doc map[string]any

	err := json.Unmarshal(iv.Policy.HuJSON(), &doc)
	if err != nil {
		panic(fmt.Sprintf("policymodel: own document does not parse: %v", err))
	}

	reserved := ReservedCaps[iv.Spelling]
	all := []any{"*"}

	add := func(section string, entry map[string]any) {
		list, _ := doc[section].([]any)
		doc[section] = slices.Insert(list, min(iv.At, len(list)), any(entry))
	}

	accept := func(src, dst string) map[string]any {
		return map[string]any{"action": "accept", "src": []any{src}, "dst": []any{dst}}
	}

	switch iv.Defect {
	case DefectReservedAttr:
		add("nodeAttrs", map[string]any{"target": all, "attr": []any{reserved}})
	case DefectReservedApp:
		add("grants", map[string]any{"src": all, "dst": all, "app": map[string]any{reserved: []any{map[string]any{}}}})
	case DefectSelfSource:
		add("acls", accept("autogroup:self", "*:*"))
	case DefectUndefinedTag:
		add("acls", accept("*", "tag:undefined:*"))
	case DefectUndefinedGroup:
		add("acls", accept("group:undefined", "*:*"))
	case DefectUndefinedHost:
		add("acls", accept("*", "h-undefined:*"))
	case DefectDefaultRouteDst:
		add("grants", map[string]any{"src": all, "dst": []any{"0.0.0.0/0"}, "ip": all})
	case DefectAppToInternet:
		add("grants", map[string]any{"src": all, "dst": []any{"autogroup:internet"}, "app": map[string]any{Apps[0]: []any{map[string]any{}}}})
	case DefectPortsOnICMP:
		r := accept("*", "*:22")
		r["proto"] = "icmp"
		add("acls", r)
	case DefectFunnelAttr:
		add("nodeAttrs", map[string]any{"target": all, "attr": []any{"funnel"}})
	case DefectViaInACL:
		r := accept("*", "*:*")
		r["via"] = []any{Tags[0]}
		add("acls", r)
	case DefectSSHWildcardSource:
		add("ssh", map[string]any{"action": "accept", "src": all, "dst": []any{"autogroup:self"}, "users": []any{"root"}})
	case DefectTagStartsWithDigit:
		owners, _ := doc["tagOwners"].(map[string]any)
		if owners == nil {
			owners = map[string]any{}
		}

		owners["tag:1a"] = []any{}
		doc["tagOwners"] = owners
	case DefectGrantWithoutIPOrApp:
		add("grants", map[string]any{"src": all, "dst": all})
	}

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		panic(fmt.Sprintf("policymodel: %v", err))
	}

	return b
}

// GoString prints the defect and the document.
func (iv InvalidPolicy) GoString() string {
	return fmt.Sprintf("defect %s:\n%s\n", iv.Defect, iv.HuJSON())
}
