package main

import (
	"context"
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"tailscale.com/types/key"
)

// Dev command flags
var devArgs struct {
	Name   string `flag:"name,Node name"`
	User   string `flag:"user,u,User identifier"`
	Key    string `flag:"key,k,Registration key"`
	Routes string `flag:"routes,r,Comma-separated routes"`
}

// Dev command implementations

func generatePrivateKeyCommand(env *command.Env) error {
	// Generate a private key locally using Tailscale's key library
	machineKey := key.NewMachine()

	machineKeyStr, err := machineKey.MarshalText()
	if err != nil {
		return fmt.Errorf("cannot marshal private key: %w", err)
	}

	result := map[string]string{
		"private_key": string(machineKeyStr),
	}

	return outputResult(result, "Private key generated", globalArgs.Output)
}

func devCreateNodeCommand(env *command.Env) error {
	if err := requireString(devArgs.Name, "name"); err != nil {
		return err
	}
	if err := requireString(devArgs.User, "user"); err != nil {
		return err
	}
	if err := requireString(devArgs.Key, "key"); err != nil {
		return err
	}

	return withHeadscaleClient(func(ctx context.Context, client v1.HeadscaleServiceClient) error {
		request := &v1.DebugCreateNodeRequest{
			Name:   devArgs.Name,
			User:   devArgs.User,
			Key:    devArgs.Key,
			Routes: parseCommaSeparated(devArgs.Routes),
		}

		response, err := client.DebugCreateNode(ctx, request)
		if err != nil {
			return fmt.Errorf("cannot create debug node: %w", err)
		}

		return outputResult(response.GetNode(), "Debug node created", globalArgs.Output)
	})
}

// Dev command definitions

func devCommands() []*command.C {
	generateCommand := &command.C{
		Name:  "generate",
		Usage: "<subcommand> [flags]",
		Help:  "Generate various resources",
		Commands: []*command.C{
			{
				Name:  "private-key",
				Usage: "",
				Help:  "Generate a private key for the headscale server",
				Run:   generatePrivateKeyCommand,
			},
		},
	}

	devCommand := &command.C{
		Name:  "dev",
		Usage: "<subcommand> [flags] [args...]",
		Help:  "Development and testing commands",
		Commands: []*command.C{
			generateCommand,
			{
				Name:     "create-node",
				Usage:    "--name <name> --user <user> --key <key> [--routes <routes>]",
				Help:     "Create a debug node that can be registered",
				SetFlags: command.Flags(flax.MustBind, &devArgs),
				Run:      devCreateNodeCommand,
			},
		},
	}

	return []*command.C{
		devCommand,
		// Dev command aliases
		createCommandAlias(devCommand, "debug", "Development and testing commands (alias)"),
		createCommandAlias(generateCommand, "generate", "Generate various resources (alias)"),
	}
}
