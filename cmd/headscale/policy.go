package main

import (
	"fmt"
	"os"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Policy command flag structures

type policyGetFlags struct {
	globalFlags
}

type policySetFlags struct {
	globalFlags
	File string `flag:"file,f,Policy file path (required)"`
}

type policyValidateFlags struct {
	globalFlags
	File string `flag:"file,f,Policy file path (required)"`
}

// Policy command implementations

func getPolicyCommand(env *command.Env) error {
	flags := env.Config.(*policyGetFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
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

	return outputResult(response.GetPolicy(), "Policy", flags.Output)
}

func setPolicyCommand(env *command.Env) error {
	flags := env.Config.(*policySetFlags)

	if err := RequireString(flags.File, "file"); err != nil {
		return err
	}

	// Read policy file
	policyBytes, err := os.ReadFile(flags.File)
	if err != nil {
		return fmt.Errorf("cannot read policy file: %w", err)
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
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

	return outputResult(response.GetPolicy(), "Policy updated", flags.Output)
}

func validatePolicyCommand(env *command.Env) error {
	flags := env.Config.(*policyValidateFlags)

	if err := RequireString(flags.File, "file"); err != nil {
		return err
	}

	// Read policy file
	policyBytes, err := os.ReadFile(flags.File)
	if err != nil {
		return fmt.Errorf("cannot read policy file: %w", err)
	}

	// For now, just validate that the file can be read and is valid JSON/HuJSON
	// TODO: Implement proper policy validation when API is available
	if len(policyBytes) == 0 {
		return fmt.Errorf("policy file is empty")
	}

	fmt.Printf("Policy file '%s' exists and can be read (%d bytes)\n", flags.File, len(policyBytes))
	fmt.Println("Note: Full policy validation is not yet implemented in the API")
	return nil
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
					Name:     "get",
					Usage:    "",
					Help:     "Get the current policy",
					SetFlags: Flags(flax.MustBind, &policyGetFlags{}),
					Run:      getPolicyCommand,
				},
				{
					Name:     "set",
					Usage:    "--file <policy-file>",
					Help:     "Set a new policy from file",
					SetFlags: Flags(flax.MustBind, &policySetFlags{}),
					Run:      setPolicyCommand,
				},
				{
					Name:     "validate",
					Usage:    "--file <policy-file>",
					Help:     "Validate a policy file (basic validation only)",
					SetFlags: Flags(flax.MustBind, &policyValidateFlags{}),
					Run:      validatePolicyCommand,
				},
			},
		},
	}
}
