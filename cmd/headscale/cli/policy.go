package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/spf13/cobra"
	"tailscale.com/util/multierr"
)

const (
	bypassFlag = "bypass-server-and-access-database-directly" //nolint:gosec // not a credential
)

var errAborted = errors.New("command aborted by user")

// bypassDatabase opens the database directly, bypassing the running server.
// The caller must close the returned handle.
func bypassDatabase() (*db.HSDatabase, error) {
	cfg, err := types.LoadServerConfig()
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	d, err := db.NewHeadscaleDatabase(cfg)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	return d, nil
}

// openBypassDB confirms the destructive bypass action and opens the database
// directly. The caller is responsible for closing the returned handle.
//
// Only the mutating policy set guards against a running server; check and
// get read the database directly against a live server by design — the
// integration harness runs policy check --bypass --force non-interactively
// against a running headscale.
func openBypassDB(cmd *cobra.Command) (*db.HSDatabase, error) {
	if !confirmAction(cmd, "This command opens the headscale database directly, bypassing the API. Only policy set refuses while a headscale answers on the configured unix socket; continue?") {
		return nil, errAborted
	}

	return bypassDatabase()
}

// refuseWhileServerRuns rejects the mutating bypass when a headscale
// answering on the configured unix socket is provably running on this
// host: the bypass would race a live instance for the database. The probe
// is fail-open — a socket that does not answer, or a config that does not
// load, is the prompt's and the caller's to judge.
// errBypassServerRunning is the refusal's wrapped static base: the probe
// answers only this one question, so the refusal never invents a new error.
var errBypassServerRunning = errors.New("headscale appears to be running")

// refuseWhileServerRuns reports whether the bypass must refuse: a server
// answering on the configured unix socket is provably running on this
// host: the bypass would race a live instance for the database. The probe
// is fail-open — a socket that does not answer, or a config that does not
// load, is the prompt's and the caller's to judge.
func refuseWhileServerRuns() error {
	cfg, cfgErr := types.LoadServerConfig()
	if cfgErr == nil && cfg.UnixSocket != "" {
		dialer := net.Dialer{Timeout: time.Second}

		conn, dialErr := dialer.DialContext(context.Background(), "unix", cfg.UnixSocket)
		if dialErr == nil {
			conn.Close()

			return fmt.Errorf("%w (unix socket %s answered); stop it before using %s", errBypassServerRunning, cfg.UnixSocket, bypassFlag)
		}
	}

	return nil
}

func init() {
	rootCmd.AddCommand(policyCmd)

	getPolicy.Flags().BoolP(bypassFlag, "", false, "Uses the headscale config to directly access the database, bypassing the API and does not require the server to be running. Allowed while a server runs; only policy set refuses then.")
	policyCmd.AddCommand(getPolicy)

	setPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	setPolicy.Flags().BoolP(bypassFlag, "", false, "Stores the policy after validating it against the persisted users and nodes; evaluates its tests and sshTests, and refuses while a headscale answers on the configured unix socket")
	mustMarkRequired(setPolicy, "file")
	policyCmd.AddCommand(setPolicy)

	checkPolicy.Flags().StringP("file", "f", "", "Path to a policy file in HuJSON format")
	checkPolicy.Flags().BoolP(bypassFlag, "", false, "Check against persisted users and nodes instead of the live server; both modes evaluate tests and sshTests. Allowed while a server runs; only policy set refuses then.")
	mustMarkRequired(checkPolicy, "file")
	policyCmd.AddCommand(checkPolicy)
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage the Headscale ACL Policy",
}

var getPolicy = &cobra.Command{
	Use:     "get",
	Short:   "Print the current ACL Policy",
	Aliases: []string{cmdShow, "view", "fetch"},
	RunE: func(cmd *cobra.Command, args []string) error {
		var policyData string

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			d, err := openBypassDB(cmd)
			if err != nil {
				return err
			}
			defer d.Close()

			pol, err := d.GetPolicy()
			if err != nil {
				return fmt.Errorf("loading policy from database: %w", err)
			}

			policyData = pol.Data
		} else {
			err := withClient(func(ctx context.Context, client *clientv1.ClientWithResponses) error {
				resp, err := client.GetPolicyWithResponse(ctx)
				if err != nil {
					return fmt.Errorf("loading ACL policy: %w", err)
				}

				if resp.StatusCode() != http.StatusOK {
					return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
				}

				policyData = resp.JSON200.Policy

				return nil
			})
			if err != nil {
				return err
			}
		}

		// This does not pass output format as we don't support yaml, json or
		// json-line output for this command. It is HuJSON already.
		fmt.Println(policyData)

		return nil
	},
}

var setPolicy = &cobra.Command{
	Use:     "set",
	Short:   "Updates the ACL Policy",
	Aliases: []string{"put", "update"},
	Long: `
	Updates the existing ACL Policy with the provided policy. The policy must be a valid HuJSON object.
	This command stores the policy in the database. The policy's tests and sshTests are evaluated against
	the persisted users and nodes before it is stored, and the bypass refuses while a headscale answers on
	the configured unix socket. Updates through the running server require policy.mode to be set to "database".`,
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			// The write path refuses while a server answers on the
			// configured unix socket: it would race a live instance for
			// the database and leave its in-memory policy stale. The
			// prompt is force-skippable; this guard is not.
			refusal := refuseWhileServerRuns()
			if refusal != nil {
				return refusal
			}

			d, err := openBypassDB(cmd)
			if err != nil {
				return err
			}
			defer d.Close()

			users, err := d.ListUsers(nil)
			if err != nil {
				return fmt.Errorf("loading users for policy validation: %w", err)
			}

			nodes, err := d.ListNodes()
			if err != nil {
				return fmt.Errorf("loading nodes for policy validation: %w", err)
			}

			// Compile against the persisted users and nodes and evaluate
			// the tests blocks, as the running server's set does: a stopped
			// server must not be able to store a document whose tests fail.
			pm, err := policyv2.NewPolicyManager(policyBytes, users, nodes.ViewSlice())
			if err != nil {
				return fmt.Errorf("parsing policy file: %w", err)
			}

			err = multierr.New(pm.RunTests(), pm.RunSSHTests())
			if err != nil {
				return fmt.Errorf("evaluating policy tests: %w", err)
			}

			// Defensive parity with the running server's set, which also
			// compiles one node's SSH policy. A parsed document cannot
			// fail here today — unknown SSH actions are rejected at parse
			// time — so the mirror only keeps the two paths from diverging
			// if the compile ever starts failing on documents.
			if len(nodes) > 0 {
				cfg, err := types.LoadServerConfig()
				if err != nil {
					return fmt.Errorf("loading server config: %w", err)
				}

				_, sshErr := pm.SSHPolicy(cfg.ServerURL, nodes.ViewSlice().At(0))
				if sshErr != nil {
					return fmt.Errorf("verifying SSH rules: %w", sshErr)
				}
			}

			_, err = d.SetPolicy(string(policyBytes))
			if err != nil {
				return fmt.Errorf("setting ACL policy: %w", err)
			}
		} else {
			policyStr := string(policyBytes)

			err := withClient(func(ctx context.Context, client *clientv1.ClientWithResponses) error {
				resp, err := client.SetPolicyWithResponse(ctx, clientv1.SetPolicyJSONRequestBody{
					Policy: &policyStr,
				})
				if err != nil {
					return fmt.Errorf("setting ACL policy: %w", err)
				}

				if resp.StatusCode() != http.StatusOK {
					return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
				}

				return nil
			})
			if err != nil {
				return err
			}
		}

		fmt.Println("Policy updated.")

		return nil
	},
}

var checkPolicy = &cobra.Command{
	Use:   "check",
	Short: "Check the Policy file for errors",
	Long: `
	Check validates the policy against the server's live users and nodes,
	running any "tests" or "sshTests" block. By default the command calls a
	running headscale over its API; pass --` + bypassFlag + ` to
	open the database directly; allowed while a server runs, only policy
	set refuses then.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		policyPath, _ := cmd.Flags().GetString("file")

		policyBytes, err := os.ReadFile(policyPath)
		if err != nil {
			return fmt.Errorf("reading policy file: %w", err)
		}

		if bypass, _ := cmd.Flags().GetBool(bypassFlag); bypass {
			d, err := openBypassDB(cmd)
			if err != nil {
				return err
			}
			defer d.Close()

			users, err := d.ListUsers(nil)
			if err != nil {
				return fmt.Errorf("loading users: %w", err)
			}

			nodes, err := d.ListNodes()
			if err != nil {
				return fmt.Errorf("loading nodes: %w", err)
			}

			// A compile only warns about failing tests, so a stale stored
			// policy cannot block boot; a check has to fail on them.
			pm, err := policyv2.NewPolicyManager(policyBytes, users, nodes.ViewSlice())
			if err != nil {
				return fmt.Errorf("parsing policy file: %w", err)
			}

			err = multierr.New(pm.RunTests(), pm.RunSSHTests())
			if err != nil {
				return err
			}

			fmt.Println("Policy is valid")

			return nil
		}

		policyStr := string(policyBytes)

		err = withClient(func(ctx context.Context, client *clientv1.ClientWithResponses) error {
			resp, err := client.CheckPolicyWithResponse(ctx, clientv1.CheckPolicyJSONRequestBody{
				Policy: &policyStr,
			})
			if err != nil {
				return err
			}

			if resp.StatusCode() != http.StatusOK {
				return apiError(resp.StatusCode(), resp.ApplicationproblemJSONDefault)
			}

			return nil
		})
		if err != nil {
			return err
		}

		fmt.Println("Policy is valid")

		return nil
	},
}
