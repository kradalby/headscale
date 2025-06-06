package main

import (
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"tailscale.com/types/key"
)

// Dev command flag structures

type devGenerateFlags struct {
	globalFlags
}

type devCreateNodeFlags struct {
	globalFlags
	userFlags
	Name   string   `flag:"name,Node name (required)"`
	Key    string   `flag:"key,k,Registration key (required)"`
	Routes []string `flag:"routes,r,Comma-separated routes"`
}

// Dev command implementations

func generatePrivateKeyCommand(env *command.Env) error {
	flags := env.Config.(*devGenerateFlags)

	// Generate a private key locally using Tailscale's key library
	machineKey := key.NewMachine()

	machineKeyStr, err := machineKey.MarshalText()
	if err != nil {
		return fmt.Errorf("cannot marshal private key: %w", err)
	}

	result := map[string]string{
		"private_key": string(machineKeyStr),
	}

	return outputResult(result, "Private key generated", flags.Output)
}

func devCreateNodeCommand(env *command.Env) error {
	flags := env.Config.(*devCreateNodeFlags)

	if err := RequireString(flags.Name, "name"); err != nil {
		return err
	}
	if err := RequireString(flags.User, "user"); err != nil {
		return err
	}
	if err := RequireString(flags.Key, "key"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.DebugCreateNodeRequest{
		Name:   flags.Name,
		User:   flags.User,
		Key:    flags.Key,
		Routes: flags.Routes,
	}

	response, err := client.DebugCreateNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot create debug node: %w", err)
	}

	return outputResult(response.GetNode(), "Debug node created", flags.Output)
}

// Dev command definitions

func devCommands() []*command.C {
	return []*command.C{
		{
			Name:  "dev",
			Usage: "<subcommand> [flags] [args...]",
			Help:  "Development and testing commands",
			Commands: []*command.C{
				{
					Name:  "generate",
					Usage: "<subcommand> [flags]",
					Help:  "Generate various resources",
					Commands: []*command.C{
						{
							Name:     "private-key",
							Usage:    "",
							Help:     "Generate a private key for the headscale server",
							SetFlags: Flags(flax.MustBind, &devGenerateFlags{}),
							Run:      generatePrivateKeyCommand,
						},
					},
				},
				{
					Name:     "create-node",
					Usage:    "--name <name> --user <user> --key <key> [--routes <routes>]",
					Help:     "Create a debug node that can be registered",
					SetFlags: Flags(flax.MustBind, &devCreateNodeFlags{}),
					Run:      devCreateNodeCommand,
				},
			},
		},
		// Dev command aliases
		{
			Name:     "debug",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Development and testing commands (alias)",
			Commands: devCommands()[0].Commands,
			Unlisted: true,
		},
		{
			Name:     "generate",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Generate various resources (alias)",
			Commands: devCommands()[0].Commands[0].Commands, // Just the generate subcommands
			Unlisted: true,
		},
	}
}
