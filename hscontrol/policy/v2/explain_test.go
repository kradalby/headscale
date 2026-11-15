package v2

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/views"
)

func TestExplainExactTuple(t *testing.T) {
	u := types.User{Name: "u"}
	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)
	b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", u)
	raw := []byte(`{"grants":[// permit dns only
 {"src":["100.64.0.1"],"dst":["100.64.0.2"],"ip":["udp:53"]},
 {"src":["100.64.0.1"],"dst":["100.64.0.2"],"ip":["udp:53"]}]}`)
	pm, err := NewPolicyManager(raw, nil, views.SliceOf([]types.NodeView{a.View(), b.View()}))
	require.NoError(t, err)

	q := AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: netip.MustParseAddr("100.64.0.1"), DestinationIP: netip.MustParseAddr("100.64.0.2"), Protocol: 17, Port: 53}
	got := pm.ExplainAccess(q, raw)
	require.Equal(t, "allowed", got.Packet)
	require.Len(t, got.Rules, 2)
	require.Equal(t, "/grants/0", got.Rules[0].Pointer)
	require.Contains(t, got.Rules[0].Comments, "permit dns")

	q.Protocol = 6
	require.Equal(t, "denied", pm.ExplainAccess(q, raw).Packet)
	q.Protocol = 17
	q.Port = 54
	require.Equal(t, "denied", pm.ExplainAccess(q, raw).Packet)
	q.Port = 53
	q.SourceIP = netip.MustParseAddr("fd7a:115c:a1e0::1")
	q.DestinationIP = netip.MustParseAddr("fd7a:115c:a1e0::2")
	require.Equal(t, "denied", pm.ExplainAccess(q, raw).Packet)
	require.Contains(t, string(raw), "// permit dns")
}

func TestExplainDefaultAndEmpty(t *testing.T) {
	u := types.User{Name: "u"}
	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)

	b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", u)
	for _, tt := range []struct {
		raw    string
		want   string
		reason string
	}{{"", "allowed", "default policy"}, {"{}", "allowed", "default policy"}, {`{"grants":[]}`, "denied", "no matching allow"}} {
		pm, err := NewPolicyManager([]byte(tt.raw), nil, views.SliceOf([]types.NodeView{a.View(), b.View()}))
		require.NoError(t, err)

		got := pm.ExplainAccess(AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: netip.MustParseAddr("100.64.0.1"), DestinationIP: netip.MustParseAddr("100.64.0.2"), Protocol: 6, Port: 22}, []byte(tt.raw))
		require.Equal(t, tt.want, got.Packet)
		require.Equal(t, tt.reason, got.Reason)
	}
}

func TestExplainRuleKinds(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		proto     uint8
		port      uint16
		want      string
		refs      int
		caps      int
		tagged    bool
	}{
		{name: "overlap ACL expansion", raw: `{"grants":[{"src":["*"],"dst":["100.64.0.2"],"ip":["tcp:80-90"]}],"acls":[{"action":"accept","src":["*"],"dst":["100.64.0.2:85","100.64.0.3:85"]}]}`, proto: 6, port: 85, want: "allowed", refs: 2},
		{name: "nil contribution slot", raw: `{"tagOwners":{"tag:missing":["u@"]},"grants":[{"src":["tag:missing"],"dst":["*"],"ip":["*"]},{"src":["*"],"dst":["100.64.0.2"],"ip":["tcp:85"]}]}`, proto: 6, port: 85, want: "allowed", refs: 1},
		{name: "numeric nonport", raw: `{"grants":[{"src":["*"],"dst":["*"],"ip":["47:*"]}]}`, proto: 47, want: "allowed", refs: 1},
		{name: "capabilities alone", raw: `{"grants":[{"src":["*"],"dst":["*"],"app":{"example.com/cap":[{}]}}]}`, proto: 6, port: 22, want: "denied", caps: 1},
		{name: "self", raw: `{"grants":[{"src":["u@"],"dst":["autogroup:self"],"ip":["tcp:22"]}]}`, proto: 6, port: 22, want: "allowed", refs: 1},
		{name: "tagged creator cannot self", raw: `{"grants":[{"src":["u@"],"dst":["autogroup:self"],"ip":["tcp:22"]}]}`, proto: 6, port: 22, want: "denied", tagged: true},
		{name: "groups hosts", raw: `{"groups":{"group:ops":["u@"]},"hosts":{"server":"100.64.0.2"},"grants":[{"src":["group:ops"],"dst":["server"],"ip":["tcp:22"]}]}`, proto: 6, port: 22, want: "allowed", refs: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			u := types.User{ID: 1, Name: "u"}
			a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)
			b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", u)
			a.ID = 1

			b.ID = 2
			if tt.tagged {
				b.Tags = []string{"tag:server"}
			}

			raw := []byte(tt.raw)
			pm, err := NewPolicyManager(raw, []types.User{u}, views.SliceOf([]types.NodeView{a.View(), b.View()}))
			require.NoError(t, err)

			q := AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: *a.IPv4, DestinationIP: *b.IPv4, Protocol: tt.proto, Port: tt.port}
			got := pm.ExplainAccess(q, raw)
			require.Empty(t, got.Diagnostic)
			require.Equal(t, tt.want, got.Packet)
			require.Len(t, got.Rules, tt.refs)
			require.Len(t, got.Capabilities, tt.caps)

			if tt.name == "self" {
				require.NotNil(t, got.Rules[0].DestinationMatch)
				require.Equal(t, "autogroup:self", got.Rules[0].DestinationMatch.Selector)
			}

			if tt.name == "tagged creator cannot self" {
				require.Nil(t, got.Checks[0].Rule.DestinationMatch)
			}

			ranges, err := pm.SummarizeAccess(a.View(), b.View())
			require.NoError(t, err)

			if tt.want == "allowed" || tt.caps > 0 {
				require.NotEmpty(t, ranges)
			}
			// Reversing initiation never acquires permission from an address-specific source.
			if tt.name == "groups hosts" {
				q.Source = b.View()
				q.SourceIP = *b.IPv4
				q.DestinationIP = *a.IPv4
				q.Destination = a.View()
				require.Equal(t, "denied", pm.ExplainAccess(q, raw).Packet)
			}

			mismatch := pm.ExplainAccess(q, []byte(`{}`))
			require.Contains(t, mismatch.Diagnostic, "source does not match")
		})
	}
}

func TestExplainSSH(t *testing.T) {
	u := types.User{ID: 1, Name: "u"}
	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)
	b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", u)
	a.ID = 1
	b.ID = 2

	for _, tt := range []struct{ action, user, want string }{{"accept", "root", "allowed"}, {"check", "root", "conditional"}, {"accept", "nobody", "denied"}} {
		t.Run(tt.action+tt.user, func(t *testing.T) {
			raw := []byte(`{"grants":[],"ssh":[{"action":"` + tt.action + `","src":["u@"],"dst":["autogroup:self"],"users":["root"]}]}`)
			pm, err := NewPolicyManager(raw, []types.User{u}, views.SliceOf([]types.NodeView{a.View(), b.View()}))
			require.NoError(t, err)

			got := pm.ExplainAccess(AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: *a.IPv4, DestinationIP: *b.IPv4, Protocol: 6, Port: 22, SSHUser: tt.user}, raw)
			require.Equal(t, "denied", got.Packet)
			require.Equal(t, tt.want, got.SSH)

			if tt.want != "denied" {
				require.Len(t, got.SSHRules, 1)
				require.Equal(t, "/ssh/0", got.SSHRules[0].Pointer)
				require.NotNil(t, got.SSHRules[0].DestinationMatch)
				require.Equal(t, "autogroup:self", got.SSHRules[0].DestinationMatch.Selector)
			}
		})
	}
}

func TestExplainRoutedContributions(t *testing.T) {
	u := types.User{ID: 1, Name: "u"}
	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)
	a.ID = 1

	for _, tt := range []struct {
		name, raw, route, dst string
		tagged                bool
	}{
		{"via", `{"tagOwners":{"tag:router":["u@"]},"grants":[{"src":["u@"],"dst":["10.0.0.0/24"],"ip":["tcp:443"],"via":["tag:router"]}]}`, "10.0.0.0/24", "10.0.0.7", true},
		{"exit self", `{"grants":[{"src":["u@"],"dst":["autogroup:self"],"ip":["tcp:443"]}]}`, "0.0.0.0/0", "100.64.0.3", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			router := node("r", "100.64.0.2", "fd7a:115c:a1e0::2", types.User{ID: 2, Name: "r"})
			router.ID = 2
			router.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{netip.MustParsePrefix(tt.route)}}

			router.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix(tt.route)}
			if tt.tagged {
				router.Tags = []string{"tag:router"}
			}

			peer := node("peer", "100.64.0.3", "fd7a:115c:a1e0::3", u)
			peer.ID = 3
			raw := []byte(tt.raw)
			pm, err := NewPolicyManager(raw, []types.User{u, {ID: 2, Name: "r"}}, views.SliceOf([]types.NodeView{a.View(), router.View(), peer.View()}))
			require.NoError(t, err)

			got := pm.ExplainAccess(AccessQuery{Source: a.View(), Destination: router.View(), SourceIP: *a.IPv4, DestinationIP: netip.MustParseAddr(tt.dst), Protocol: 6, Port: 443}, raw)
			require.Equal(t, "allowed", got.Packet)
			require.Empty(t, got.Diagnostic)
			require.Len(t, got.Rules, 1)
		})
	}
}

func TestExplainSSHOnlyAndCheckPrecedence(t *testing.T) {
	u := types.User{ID: 1, Name: "u"}
	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)
	b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", u)
	a.ID = 1
	b.ID = 2
	raw := []byte(`{"ssh":[{"action":"accept","src":["u@"],"dst":["autogroup:self"],"users":["autogroup:nonroot"]},{"action":"check","src":["u@"],"dst":["autogroup:self"],"users":["autogroup:nonroot"]}]}`)
	pm, err := NewPolicyManager(raw, []types.User{u}, views.SliceOf([]types.NodeView{a.View(), b.View()}))
	require.NoError(t, err)

	got := pm.ExplainAccess(AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: *a.IPv4, DestinationIP: *b.IPv4, Protocol: 6, Port: 22, SSHUser: "alice"}, raw)
	require.Equal(t, "allowed", got.Packet)
	require.Equal(t, "default policy", got.Reason)
	require.Equal(t, "conditional", got.SSH)
	require.Len(t, got.SSHRules, 2)

	b.Tags = []string{"tag:server"}
	tagged, err := NewPolicyManager(raw, []types.User{u}, views.SliceOf([]types.NodeView{a.View(), b.View()}))
	require.NoError(t, err)

	got = tagged.ExplainAccess(AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: *a.IPv4, DestinationIP: *b.IPv4, Protocol: 6, Port: 22, SSHUser: "alice"}, raw)
	require.Equal(t, "denied", got.SSH)
	require.Empty(t, got.SSHRules)
}

func TestExplainOwnedOutputsAndFamilies(t *testing.T) {
	u := types.User{ID: 1, Name: "u"}
	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)
	b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", u)
	a.ID = 1
	b.ID = 2
	raw := []byte(`{"grants":[{"src":["*"],"dst":["*"],"ip":["tcp:22"]}]}`)
	pm, err := NewPolicyManager(raw, []types.User{u}, views.SliceOf([]types.NodeView{a.View(), b.View()}))
	require.NoError(t, err)
	ranges, err := pm.SummarizeAccess(a.View(), b.View())
	require.NoError(t, err)
	require.Len(t, ranges, 2)

	for _, r := range ranges {
		require.Equal(t, netip.MustParseAddr(r.Source).Is4(), netip.MustParseAddr(r.Destination).Is4())
	}

	ranges[0].Protocols[0] = 47
	again, err := pm.SummarizeAccess(a.View(), b.View())
	require.NoError(t, err)
	require.Equal(t, 6, again[0].Protocols[0])

	q := AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: *a.IPv4, DestinationIP: *b.IPv4, Protocol: 6, Port: 22}
	got := pm.ExplainAccess(q, raw)
	require.Equal(t, "allowed", got.Packet)
	got.Rules[0].Excerpt = "changed"
	require.NotEqual(t, "changed", pm.ExplainAccess(q, raw).Rules[0].Excerpt)
	q.DestinationIP = *b.IPv6
	require.Equal(t, "unavailable", pm.ExplainAccess(q, raw).Packet)
	q.DestinationIP = *b.IPv4
	q.SourceIP = netip.MustParseAddr("100.64.0.9")
	require.Equal(t, "unavailable", pm.ExplainAccess(q, raw).Packet)
}

func TestExplainEvidencePagesAndSourceChunks(t *testing.T) {
	u := types.User{ID: 1, Name: "u"}
	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", u)
	b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", u)
	a.ID, b.ID = 1, 2
	grant := `{"src":["group:ops"],"dst":["server"],"ip":["tcp:22"],"app":{"example.com/cap":[{}]}}`
	ssh := `{"action":"accept","src":["u@"],"dst":["autogroup:self"],"users":["root"]}`
	// A single comment larger than the HTTP response limit must never hide the verdict.
	comment := "/*" + strings.Repeat("é", 1100000) + "*/"
	grants := make([]string, 105)

	sshs := make([]string, 105)
	for i := range grants {
		grants[i], sshs[i] = grant, ssh
	}

	grants[0] = strings.Replace(grant, "{", "{/*"+strings.Repeat("rule comment", 100)+"*/", 1)
	raw := []byte(`{"groups":{"group:ops":["u@"]},"hosts":{"server":"100.64.0.2"},"grants":[` + comment + strings.Join(grants, ",") + `],"ssh":[` + strings.Join(sshs, ",") + `]}`)
	pm, err := NewPolicyManager(raw, []types.User{u}, views.SliceOf([]types.NodeView{a.View(), b.View()}))
	require.NoError(t, err)

	q := AccessQuery{Source: a.View(), Destination: b.View(), SourceIP: *a.IPv4, DestinationIP: *b.IPv4, Protocol: 6, Port: 22, SSHUser: "root"}
	first := pm.ExplainAccess(q, raw)
	require.Equal(t, "allowed", first.Packet)
	require.Equal(t, "allowed", first.SSH)
	require.Equal(t, 105, first.RulesTotal)
	require.Equal(t, 105, first.SSHRulesTotal)
	require.Equal(t, 105, first.CapabilitiesTotal)
	require.Len(t, first.Rules, 10)
	require.True(t, first.Rules[0].Truncated)
	require.LessOrEqual(t, len(first.Rules[0].Excerpt), 512)
	require.LessOrEqual(t, len(first.Rules[0].Comments), 256)
	require.Equal(t, "group:ops", first.Rules[0].SourceMatch.Selector)
	require.Equal(t, "Group", first.Rules[0].SourceMatch.Kind)
	require.Equal(t, "server", first.Rules[0].DestinationMatch.Selector)
	require.Equal(t, "100.64.0.2", first.Rules[0].DestinationMatch.Address)
	encoded, err := json.Marshal(first)
	require.NoError(t, err)
	require.Less(t, len(encoded), 100000)

	q.EvidenceOffset = 100
	last := pm.ExplainAccess(q, raw)
	require.Len(t, last.Rules, 5)
	require.Equal(t, "/grants/100", last.Rules[0].Pointer)
	require.Len(t, last.SSHRules, 5)
	require.Equal(t, "/ssh/100", last.SSHRules[0].Pointer)
	require.Len(t, last.Capabilities, 1)
	require.Len(t, last.Capabilities[0].Rules, 5)
	require.Nil(t, last.EvidenceNext)

	q.Port = 23
	denied := pm.ExplainAccess(q, raw)
	require.Equal(t, "denied", denied.Packet)
	require.Equal(t, 105, denied.ChecksTotal)
	require.Len(t, denied.Checks, 5)
	require.Equal(t, "/grants/100", denied.Checks[0].Rule.Pointer)

	var original strings.Builder

	offset := 0
	for {
		chunk, total, next, err := AccessSourceChunk(raw, "/grants/0", offset)
		require.NoError(t, err)
		require.LessOrEqual(t, len(chunk), 8192)
		original.WriteString(chunk)

		if next == nil {
			require.Equal(t, total, original.Len())
			break
		}

		require.Greater(t, *next, offset)
		offset = *next
	}

	require.Equal(t, comment+grants[0], original.String())

	q.OmitEvidence = true
	verdict := pm.ExplainAccess(q, raw)
	require.Equal(t, "denied", verdict.Packet)
	require.Empty(t, verdict.Rules)
	require.Empty(t, verdict.SSHRules)
	require.Empty(t, verdict.Capabilities)
}
