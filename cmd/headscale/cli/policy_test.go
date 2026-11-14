package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	hsconfig "github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

// TestSetPolicyBypassRunsTests pins that the bypass set evaluates the
// policy's tests before persisting, as the running-server path does: a
// stopped server must not be able to store a document whose tests fail
// against the persisted users and nodes.
func TestSetPolicyBypassRunsTests(t *testing.T) {
	dir := t.TempDir()
	// Pin the unix socket to the test's own directory: the guard probes
	// the configured socket, and the host's default must not decide
	// whether this test's refusal comes from the guard or the tests.
	socketPath := filepath.Join(dir, "headscale.sock")

	config := fmt.Sprintf(`
noise:
  private_key_path: "private.pem"
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: %q
server_url: "https://server.derp.no"
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: %q
disable_check_updates: true
`, filepath.Join(dir, "hs.db"), socketPath)

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	l, err := hsconfig.Load(configPath, true, nil)
	require.NoError(t, err)

	cfg := l.Config
	previousFile, previousLoaded := cfgFile, loaded
	cfgFile, loaded = configPath, l

	t.Cleanup(func() { cfgFile, loaded = previousFile, previousLoaded })

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("oracle")

	node := database.CreateRegisteredNodeForTest(user, "oracle-node")
	require.NoError(t, database.Close())

	// The grants allow nothing while the tests expect the user to reach
	// its own node: the document is structurally valid, and evaluating
	// its tests against the persisted nodes must refuse it.
	policy := fmt.Sprintf(`{
		"grants": [],
		"tests": [{"src": "oracle@", "accept": ["%s:22"]}]
	}`, node.IPv4.String())

	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o600))

	rootCmd.SetArgs([]string{
		"--force",
		"-c", configPath,
		"policy", "set",
		"--" + bypassFlag,
		"--file", policyPath,
	})

	err = rootCmd.Execute()
	require.ErrorContains(t, err, "evaluating policy tests", "bypass set must refuse a policy whose tests fail")

	// The refused document must not have been stored.
	database, err = db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	defer database.Close()

	_, err = database.GetPolicy()
	require.ErrorIs(t, err, types.ErrPolicyNotFound, "a refused policy must not be persisted")
}

// TestPolicyCheckBypassProceedsWhileServerRuns pins the read-only bypass
// flow against a live server: policy check and get open the database
// directly while headscale answers on the configured unix socket, as the
// integration harness does non-interactively with --force.
func TestPolicyCheckBypassProceedsWhileServerRuns(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "headscale.sock")

	var listenCfg net.ListenConfig

	listener, err := listenCfg.Listen(context.Background(), "unix", socketPath)
	require.NoError(t, err)

	defer listener.Close()

	config := fmt.Sprintf(`
noise:
  private_key_path: "private.pem"
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: %q
server_url: "https://server.derp.no"
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: %q
disable_check_updates: true
`, filepath.Join(dir, "hs.db"), socketPath)

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"acls":[]}`), 0o600))

	rootCmd.SetArgs([]string{
		"--force",
		"-c", configPath,
		"policy", "check",
		"--" + bypassFlag,
		"--file", policyPath,
	})

	err = rootCmd.Execute()
	require.NoError(t, err, "a read-only bypass must proceed while the server runs")
}

// TestSetPolicyBypassRefusesRunningServer pins the bypass guard on the
// mutating command: while a headscale answers on the configured unix
// socket, policy set must refuse to open the database, and once the
// server stops it must proceed.
func TestSetPolicyBypassRefusesRunningServer(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "headscale.sock")

	var listenCfg net.ListenConfig

	listener, err := listenCfg.Listen(context.Background(), "unix", socketPath)
	require.NoError(t, err)

	defer listener.Close()

	config := fmt.Sprintf(`
noise:
  private_key_path: "private.pem"
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: %q
server_url: "https://server.derp.no"
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: %q
disable_check_updates: true
`, filepath.Join(dir, "hs.db"), socketPath)

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"acls":[]}`), 0o600))

	rootCmd.SetArgs([]string{
		"--force",
		"-c", configPath,
		"policy", "set",
		"--" + bypassFlag,
		"--file", policyPath,
	})

	err = rootCmd.Execute()
	require.ErrorContains(t, err, "appears to be running", "bypass must refuse while the server answers")

	// The refused write must not have reached the database.
	l, err := hsconfig.Load(configPath, true, nil)
	require.NoError(t, err)

	cfg := l.Config
	previousFile, previousLoaded := cfgFile, loaded
	cfgFile, loaded = configPath, l

	t.Cleanup(func() { cfgFile, loaded = previousFile, previousLoaded })

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	defer database.Close()

	_, err = database.GetPolicy()
	require.ErrorIs(t, err, types.ErrPolicyNotFound, "a refused set must not persist a policy")

	listener.Close()

	err = rootCmd.Execute()
	require.NoError(t, err, "bypass must proceed once the server stops")
}

// TestSetPolicyBypassAcceptsValidSSH pins that the bypass set's SSH-rule
// mirror does not refuse a document the running server's set accepts: a
// positive-path pin by nature, since a parsed document cannot fail the
// SSH compile today.
func TestSetPolicyBypassAcceptsValidSSH(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "headscale.sock")

	config := fmt.Sprintf(`
noise:
  private_key_path: "private.pem"
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: %q
server_url: "https://server.derp.no"
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: %q
disable_check_updates: true
`, filepath.Join(dir, "hs.db"), socketPath)

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	l, err := hsconfig.Load(configPath, true, nil)
	require.NoError(t, err)

	cfg := l.Config
	previousFile, previousLoaded := cfgFile, loaded
	cfgFile, loaded = configPath, l

	t.Cleanup(func() { cfgFile, loaded = previousFile, previousLoaded })

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("oracle")

	database.CreateRegisteredNodeForTest(user, "oracle-node")
	require.NoError(t, database.Close())

	policy := `{
		"grants": [],
		"ssh": [{"src": ["oracle@"], "dst": ["oracle@"], "users": ["root"], "action": "check"}]
	}`

	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(policy), 0o600))

	rootCmd.SetArgs([]string{
		"--force",
		"-c", configPath,
		"policy", "set",
		"--" + bypassFlag,
		"--file", policyPath,
	})

	err = rootCmd.Execute()
	require.NoError(t, err, "a policy whose SSH rules prepare must store")

	database, err = db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	defer database.Close()

	stored, err := database.GetPolicy()
	require.NoError(t, err)
	require.Equal(t, policy, stored.Data)
}

// TestPolicySetKeepsAliases pins the long-standing put/update aliases:
// nothing else in the repo references them, so a help-text edit can drop
// them silently and only an assertion on the command notices.
func TestPolicySetKeepsAliases(t *testing.T) {
	require.Contains(t, setPolicy.Aliases, "put")
	require.Contains(t, setPolicy.Aliases, "update")
}

// TestPolicyBypassHelpMatchesGuard pins that the read-only bypass help
// states the contract the guard enforces: only policy set refuses while
// a server runs. Every read-only surface states the live-server
// contract affirmatively, and the phrase's own negation and both
// historical stopped-server wordings are banned, so a reword cannot
// drop, restate or negate these known forms without failing here.
// Substring pins cannot refute every invented wording; new forms are
// added to the bans as they appear.
func TestPolicyBypassHelpMatchesGuard(t *testing.T) {
	allowed := "allowed while a server runs"
	require.Contains(t, strings.ToLower(checkPolicy.Long), allowed,
		"the check Long must state the live-server contract")
	require.NotContains(t, strings.ToLower(checkPolicy.Long), "not "+allowed,
		"the check Long must not negate the contract")
	require.Contains(t, strings.ToLower(checkPolicy.Flags().Lookup(bypassFlag).Usage), allowed,
		"the check bypass flag help must state the live-server contract")
	require.NotContains(t, strings.ToLower(checkPolicy.Flags().Lookup(bypassFlag).Usage), "not "+allowed,
		"the check bypass flag help must not negate the contract")
	require.Contains(t, strings.ToLower(getPolicy.Flags().Lookup(bypassFlag).Usage), allowed,
		"the get bypass flag help must state the live-server contract")
	require.NotContains(t, strings.ToLower(getPolicy.Flags().Lookup(bypassFlag).Usage), "not "+allowed,
		"the get bypass flag help must not negate the contract")

	for _, cmd := range []*cobra.Command{getPolicy, checkPolicy} {
		require.NotContains(t, cmd.Long, "not running", cmd.Name())
		require.NotContains(t, cmd.Long, "stopped", cmd.Name())
	}

	for _, cmd := range []*cobra.Command{getPolicy, checkPolicy} {
		usage := cmd.Flags().Lookup(bypassFlag).Usage
		require.NotContains(t, usage, "not running", cmd.Name())
		require.NotContains(t, usage, "stopped", cmd.Name())
	}
}

// bypassGuardConfig writes a config whose unix socket is socketPath and
// returns the config path and a policy file.
func bypassGuardConfig(t *testing.T, dir, socketPath string) (string, string) {
	t.Helper()

	config := fmt.Sprintf(`
noise:
  private_key_path: "private.pem"
prefixes:
  v4: 100.64.0.0/10
database:
  type: sqlite3
  sqlite:
    path: %q
server_url: "https://server.derp.no"
dns:
  magic_dns: false
  override_local_dns: false
unix_socket: %q
disable_check_updates: true
`, filepath.Join(dir, "hs.db"), socketPath)

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte(config), 0o600))

	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"acls":[]}`), 0o600))

	return configPath, policyPath
}

// TestSetPolicyBypassRefusesUnprovenSocket pins that the guard fails
// closed: a socket the probe cannot connect to for any reason other than
// it being gone or unbound may front a live server, so policy set refuses.
// A stale socket file left by a stopped server proves nothing runs.
func TestSetPolicyBypassRefusesUnprovenSocket(t *testing.T) {
	previousFile, previousLoaded := cfgFile, loaded

	t.Cleanup(func() { cfgFile, loaded = previousFile, previousLoaded })
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "headscale.sock")

	var listenCfg net.ListenConfig

	listener, err := listenCfg.Listen(context.Background(), "unix", socketPath)
	require.NoError(t, err)

	unix, ok := listener.(*net.UnixListener)
	require.True(t, ok)
	unix.SetUnlinkOnClose(false)

	// A server whose socket this user may not open: the dial fails with a
	// permission error, which does not show the server is gone. Root may
	// still connect, which the guard refuses as a server that answered.
	require.NoError(t, os.Chmod(socketPath, 0))

	configPath, policyPath := bypassGuardConfig(t, dir, socketPath)

	rootCmd.SetArgs([]string{
		"--force",
		"-c", configPath,
		"policy", "set",
		"--" + bypassFlag,
		"--file", policyPath,
	})

	err = rootCmd.Execute()
	require.ErrorContains(t, err, "appears to be running", "an unreadable socket must not count as no server")

	// The server stops but leaves its socket file: nothing is bound to it.
	require.NoError(t, listener.Close())
	require.NoError(t, os.Chmod(socketPath, 0o600))

	_, err = os.Stat(socketPath)
	require.NoError(t, err, "test sanity: the stale socket file remains")

	err = rootCmd.Execute()
	require.NoError(t, err, "a stale socket file must not block the bypass")
}

// TestSetPolicyBypassRefusesUnloadableConfig pins that a config the guard
// cannot load stops policy set instead of skipping the probe.
func TestSetPolicyBypassRefusesUnloadableConfig(t *testing.T) {
	dir := t.TempDir()

	configPath := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("prefixes:\n  v4: not-a-prefix\n"), 0o600))

	policyPath := filepath.Join(dir, "policy.json")
	require.NoError(t, os.WriteFile(policyPath, []byte(`{"acls":[]}`), 0o600))

	rootCmd.SetArgs([]string{
		"--force",
		"-c", configPath,
		"policy", "set",
		"--" + bypassFlag,
		"--file", policyPath,
	})

	previousFile := cfgFile
	cfgFile = configPath

	t.Cleanup(func() { cfgFile = previousFile })

	previousPolicy := setPolicy.Flags().Lookup("file").Value.String()
	previousBypass := setPolicy.Flags().Lookup(bypassFlag).Value.String()
	require.NoError(t, setPolicy.Flags().Set("file", policyPath))
	require.NoError(t, setPolicy.Flags().Set(bypassFlag, "true"))
	t.Cleanup(func() {
		_ = setPolicy.Flags().Set("file", previousPolicy)
		_ = setPolicy.Flags().Set(bypassFlag, previousBypass)
	})
	// The normal initializer exits on invalid config; exercise the bypass guard directly.
	err := setPolicy.RunE(setPolicy, nil)
	require.ErrorContains(t, err, "loading config", "the guard must surface an unloadable config")
}
