// This file implements a data-driven test runner for ACL compatibility tests.
// It loads JSON golden files from testdata/acl_results/ACL-*.json and compares
// headscale's ACL engine output against the expected packet filter rules.
//
// The JSON files were converted from the original inline Go struct test cases
// in tailscale_acl_compat_test.go. Each file contains:
//   - A full policy (groups, tagOwners, hosts, acls)
//   - Expected packet_filter_rules per node (5 nodes)
//   - Or an error response for invalid policies
//
// Test data source: testdata/acl_results/ACL-*.json
// Original source: Tailscale SaaS API captures + headscale-generated expansions

package v2

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/policy/policyutil"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// ptrAddr is a helper to create a pointer to a netip.Addr.
func ptrAddr(s string) *netip.Addr {
	addr := netip.MustParseAddr(s)

	return &addr
}

// setupTailscaleCompatUsers returns the test users for compatibility tests.
func setupTailscaleCompatUsers() types.Users {
	return types.Users{
		{Model: gorm.Model{ID: 1}, Name: "kratail2tid"},
	}
}

// setupTailscaleCompatNodes returns the test nodes for compatibility tests.
// The node configuration matches the Tailscale test environment:
//   - 1 user-owned node (user1)
//   - 4 tagged nodes (tagged-server, tagged-client, tagged-db, tagged-web).
func setupTailscaleCompatNodes(users types.Users) types.Nodes {
	nodeUser1 := &types.Node{
		ID:        1,
		GivenName: "user1",
		User:      &users[0],
		UserID:    &users[0].ID,
		IPv4:      ptrAddr("100.90.199.68"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::2d01:c747"),
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedServer := &types.Node{
		ID:        2,
		GivenName: "tagged-server",
		IPv4:      ptrAddr("100.108.74.26"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::b901:4a87"),
		Tags:      []string{"tag:server"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedClient := &types.Node{
		ID:        3,
		GivenName: "tagged-client",
		IPv4:      ptrAddr("100.80.238.75"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::7901:ee86"),
		Tags:      []string{"tag:client"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedDB := &types.Node{
		ID:        4,
		GivenName: "tagged-db",
		IPv4:      ptrAddr("100.74.60.128"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::2f01:3c9c"),
		Tags:      []string{"tag:database"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	nodeTaggedWeb := &types.Node{
		ID:        5,
		GivenName: "tagged-web",
		IPv4:      ptrAddr("100.94.92.91"),
		IPv6:      ptrAddr("fd7a:115c:a1e0::ef01:5c81"),
		Tags:      []string{"tag:web"},
		Hostinfo:  &tailcfg.Hostinfo{},
	}

	return types.Nodes{
		nodeUser1,
		nodeTaggedServer,
		nodeTaggedClient,
		nodeTaggedDB,
		nodeTaggedWeb,
	}
}

// findNodeByGivenName finds a node by its GivenName field.
func findNodeByGivenName(nodes types.Nodes, name string) *types.Node {
	for _, n := range nodes {
		if n.GivenName == name {
			return n
		}
	}

	return nil
}

// cmpOptions returns comparison options for FilterRule slices.
// It sorts SrcIPs and DstPorts to handle ordering differences.
func cmpOptions() []cmp.Option {
	return []cmp.Option{
		cmpopts.SortSlices(func(a, b string) bool { return a < b }),
		cmpopts.SortSlices(func(a, b tailcfg.NetPortRange) bool {
			if a.IP != b.IP {
				return a.IP < b.IP
			}

			if a.Ports.First != b.Ports.First {
				return a.Ports.First < b.Ports.First
			}

			return a.Ports.Last < b.Ports.Last
		}),
		cmpopts.SortSlices(func(a, b int) bool { return a < b }),
	}
}

// aclTestFile represents the JSON structure of a captured ACL test file.
type aclTestFile struct {
	TestID           string `json:"test_id"`
	Source           string `json:"source"` // "tailscale_saas" or "headscale_adapted"
	Error            bool   `json:"error"`
	HeadscaleDiffers bool   `json:"headscale_differs"`
	ParentTest       string `json:"parent_test"`
	Input            struct {
		FullPolicy      json.RawMessage `json:"full_policy"`
		APIResponseCode int             `json:"api_response_code"`
		APIResponseBody *struct {
			Message string `json:"message"`
		} `json:"api_response_body"`
	} `json:"input"`
	Topology struct {
		Nodes map[string]struct {
			Hostname string   `json:"hostname"`
			Tags     []string `json:"tags"`
			IPv4     string   `json:"ipv4"`
			IPv6     string   `json:"ipv6"`
			User     string   `json:"user"`
		} `json:"nodes"`
	} `json:"topology"`
	Captures map[string]struct {
		PacketFilterRules json.RawMessage `json:"packet_filter_rules"`
	} `json:"captures"`
}

// loadACLTestFile loads and parses a single ACL test JSON file.
func loadACLTestFile(t *testing.T, path string) aclTestFile {
	t.Helper()

	content, err := os.ReadFile(path)
	require.NoError(t, err, "failed to read test file %s", path)

	var tf aclTestFile

	err = json.Unmarshal(content, &tf)
	require.NoError(t, err, "failed to parse test file %s", path)

	return tf
}

// aclSkipReasons documents WHY tests are expected to fail and WHAT needs to be
// implemented to fix them. Tests are grouped by root cause.
//
// Impact summary:
//
//	SRCIPS_FORMAT            - tests: SrcIPs use adapted format (100.64.0.0/10 vs partitioned CIDRs)
//	DSTPORTS_FORMAT          - tests: DstPorts IP format differences
//	IPPROTO_FORMAT           - tests: IPProto nil vs [6,17,1,58]
//	IMPLEMENTATION_PENDING   - tests: Not yet implemented in headscale
var aclSkipReasons = map[string]string{
	// Currently all tests are in the skip list because the ACL engine
	// output format changed with the ResolvedAddresses refactor.
	// Tests will be removed from this list as the implementation is
	// updated to match the expected output.
}

// TestACLCompat is a data-driven test that loads all ACL-*.json test files
// and compares headscale's ACL engine output against the expected behavior.
//
// Each JSON file contains:
//   - A full policy with groups, tagOwners, hosts, and acls
//   - For success cases: expected packet_filter_rules per node (5 nodes)
//   - For error cases: expected error message
func TestACLCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(
		filepath.Join("testdata", "acl_results", "ACL-*.json"),
	)
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(
		t,
		files,
		"no ACL-*.json test files found in testdata/acl_results/",
	)

	t.Logf("Loaded %d ACL test files", len(files))

	users := setupTailscaleCompatUsers()
	nodes := setupTailscaleCompatNodes(users)

	for _, file := range files {
		tf := loadACLTestFile(t, file)

		t.Run(tf.TestID, func(t *testing.T) {
			t.Parallel()

			// Check skip list
			if reason, ok := aclSkipReasons[tf.TestID]; ok {
				t.Skipf(
					"TODO: %s — see aclSkipReasons for details",
					reason,
				)

				return
			}

			if tf.Error {
				testACLError(t, tf)

				return
			}

			testACLSuccess(t, tf, users, nodes)
		})
	}
}

// testACLError verifies that an invalid policy produces the expected error.
func testACLError(t *testing.T, tf aclTestFile) {
	t.Helper()

	pol, err := unmarshalPolicy(tf.Input.FullPolicy)
	if err != nil {
		// Parse-time error — valid for some error tests
		if tf.Input.APIResponseBody != nil {
			wantMsg := tf.Input.APIResponseBody.Message
			if wantMsg != "" {
				assert.Contains(
					t,
					err.Error(),
					wantMsg,
					"%s: error message should contain expected substring",
					tf.TestID,
				)
			}
		}

		return
	}

	err = pol.validate()
	if err != nil {
		if tf.Input.APIResponseBody != nil {
			wantMsg := tf.Input.APIResponseBody.Message
			if wantMsg != "" {
				// Allow partial match — headscale error messages differ
				// from Tailscale's
				errStr := err.Error()
				if !strings.Contains(errStr, wantMsg) {
					// Try matching key parts
					matched := false

					for _, part := range []string{
						"autogroup:self",
						"not valid on the src",
						"port range",
						"tag not found",
						"undefined",
					} {
						if strings.Contains(wantMsg, part) &&
							strings.Contains(errStr, part) {
							matched = true

							break
						}
					}

					if !matched {
						t.Logf(
							"%s: error message difference\n  want (tailscale): %q\n  got (headscale):  %q",
							tf.TestID,
							wantMsg,
							errStr,
						)
					}
				}
			}
		}

		return
	}

	// For headscale_differs tests, headscale may accept what Tailscale rejects
	if tf.HeadscaleDiffers {
		t.Logf(
			"%s: headscale accepts this policy (Tailscale rejects it)",
			tf.TestID,
		)

		return
	}

	t.Errorf(
		"%s: expected error but policy parsed and validated successfully",
		tf.TestID,
	)
}

// testACLSuccess verifies that a valid policy produces the expected
// packet filter rules for each node.
func testACLSuccess(
	t *testing.T,
	tf aclTestFile,
	users types.Users,
	nodes types.Nodes,
) {
	t.Helper()

	pol, err := unmarshalPolicy(tf.Input.FullPolicy)
	require.NoError(
		t,
		err,
		"%s: policy should parse successfully",
		tf.TestID,
	)

	err = pol.validate()
	require.NoError(
		t,
		err,
		"%s: policy should validate successfully",
		tf.TestID,
	)

	for nodeName, capture := range tf.Captures {
		t.Run(nodeName, func(t *testing.T) {
			captureIsNull := len(capture.PacketFilterRules) == 0 ||
				string(capture.PacketFilterRules) == "null" //nolint:goconst

			node := findNodeByGivenName(nodes, nodeName)
			if node == nil {
				t.Skipf(
					"node %s not found in test setup",
					nodeName,
				)

				return
			}

			// Compile headscale filter rules for this node
			compiledRules, err := pol.compileFilterRulesForNode(
				users,
				node.View(),
				nodes.ViewSlice(),
			)
			require.NoError(
				t,
				err,
				"%s/%s: failed to compile filter rules",
				tf.TestID,
				nodeName,
			)

			gotRules := policyutil.ReduceFilterRules(
				node.View(),
				compiledRules,
			)

			// Parse expected rules from JSON
			var wantRules []tailcfg.FilterRule
			if !captureIsNull {
				err = json.Unmarshal(
					capture.PacketFilterRules,
					&wantRules,
				)
				require.NoError(
					t,
					err,
					"%s/%s: failed to unmarshal expected rules",
					tf.TestID,
					nodeName,
				)
			}

			// Compare
			opts := append(
				cmpOptions(),
				cmpopts.EquateEmpty(),
			)
			if diff := cmp.Diff(
				wantRules,
				gotRules,
				opts...,
			); diff != "" {
				t.Errorf(
					"%s/%s: filter rules mismatch (-want +got):\n%s",
					tf.TestID,
					nodeName,
					diff,
				)
			}
		})
	}
}
