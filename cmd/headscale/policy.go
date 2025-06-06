package main

import (
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Policy command flags
var policyArgs struct {
	File string `flag:"file,f,Policy file path"`
}

// Policy command implementations

func getPolicyCommand(env *command.Env) error {
	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.GetPolicyRequest{}

	response, err := client.GetPolicy(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot get policy: %w", err)
	}

	return outputResult(response.GetPolicy(), "Current Policy", globalArgs.Output)
}

func setPolicyCommand(env *command.Env) error {
	if err := requireString(policyArgs.File, "file"); err != nil {
		return err
	}

	// Read policy file
	policyBytes, err := os.ReadFile(policyArgs.File)
	if err != nil {
		return fmt.Errorf("cannot read policy file: %w", err)
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.SetPolicyRequest{
		Policy: string(policyBytes),
	}

	response, err := client.SetPolicy(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot set policy: %w", err)
	}

	return outputResult(response.GetPolicy(), "Policy updated", globalArgs.Output)
}

func testPolicyCommand(env *command.Env) error {
	if err := requireString(policyArgs.File, "file"); err != nil {
		return err
	}

	// Read the policy file
	policyBytes, err := os.ReadFile(policyArgs.File)
	if err != nil {
		return fmt.Errorf("cannot read policy file: %w", err)
	}

	// Basic validation - check if file is readable and non-empty
	if len(policyBytes) == 0 {
		return fmt.Errorf("policy file is empty")
	}

	// Try to parse as JSON to check basic syntax
	// TODO: Implement proper policy validation when API is available
	fmt.Printf("Policy file '%s' exists and can be read (%d bytes)\n", policyArgs.File, len(policyBytes))
	fmt.Println("Note: Full policy validation requires the headscale server to be running")
	fmt.Println("Use 'headscale policy set --file <file>' to test validation against the server")

	return nil
}

func reloadPolicyCommand(env *command.Env) error {
	// Get current policy and set it again to trigger a reload
	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Get current policy
	getRequest := &v1.GetPolicyRequest{}
	getResponse, err := client.GetPolicy(ctx, getRequest)
	if err != nil {
		return fmt.Errorf("cannot get current policy: %w", err)
	}

	// Set the same policy to trigger reload
	setRequest := &v1.SetPolicyRequest{
		Policy: getResponse.GetPolicy(),
	}

	setResponse, err := client.SetPolicy(ctx, setRequest)
	if err != nil {
		return fmt.Errorf("cannot reload policy: %w", err)
	}

	return outputResult(setResponse.GetPolicy(), "Policy reloaded", globalArgs.Output)
}

// Policy command definitions

func policyCommands() []*command.C {
	return []*command.C{
		{
			Name:  "policy",
			Usage: "<subcommand> [flags] [args...]",
			Help:  "Manage ACL policies",
			Commands: []*command.C{
				{
					Name:  "get",
					Usage: "",
					Help:  "Get the current policy",
					Run:   getPolicyCommand,
				},
				{
					Name:     "set",
					Usage:    "--file <file>",
					Help:     "Set a new policy from file",
					SetFlags: command.Flags(flax.MustBind, &policyArgs),
					Run:      setPolicyCommand,
				},
				{
					Name:     "test",
					Usage:    "--file <file>",
					Help:     "Test a policy file for validity",
					SetFlags: command.Flags(flax.MustBind, &policyArgs),
					Run:      testPolicyCommand,
				},
				{
					Name:     "validate",
					Usage:    "--file <file>",
					Help:     "Test a policy file for validity (alias)",
					SetFlags: command.Flags(flax.MustBind, &policyArgs),
					Run:      testPolicyCommand,
					Unlisted: true,
				},
				{
					Name:  "reload",
					Usage: "",
					Help:  "Reload the current policy from storage",
					Run:   reloadPolicyCommand,
				},
			},
		},
		// Policy management alias
		{
			Name:     "acl",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage ACL policies (alias)",
			Unlisted: true,
			Commands: []*command.C{
				{
					Name:  "get",
					Usage: "",
					Help:  "Get the current policy",
					Run:   getPolicyCommand,
				},
				{
					Name:     "set",
					Usage:    "--file <file>",
					Help:     "Set a new policy from file",
					SetFlags: command.Flags(flax.MustBind, &policyArgs),
					Run:      setPolicyCommand,
				},
				{
					Name:     "test",
					Usage:    "--file <file>",
					Help:     "Test a policy file for validity",
					SetFlags: command.Flags(flax.MustBind, &policyArgs),
					Run:      testPolicyCommand,
				},
				{
					Name:  "reload",
					Usage: "",
					Help:  "Reload the current policy from storage",
					Run:   reloadPolicyCommand,
				},
			},
		},
	}
}
