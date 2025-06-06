package main

import (
	"fmt"
	"time"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// API key command flag structures

type listAPIKeyFlags struct {
	globalFlags
}

type createAPIKeyFlags struct {
	globalFlags
	expirationFlags
}

type apiKeyActionFlags struct {
	globalFlags
	Prefix string `flag:"prefix,p,API key prefix (required)"`
}

// API key command implementations

func listAPIKeysCommand(env *command.Env) error {
	flags := env.Config.(*listAPIKeyFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ListApiKeysRequest{}

	response, err := client.ListApiKeys(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot list API keys: %w", err)
	}

	return outputResult(response.GetApiKeys(), "API Keys", flags.Output)
}

func createAPIKeyCommand(env *command.Env) error {
	flags := env.Config.(*createAPIKeyFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Parse expiration
	duration, err := time.ParseDuration(flags.Expiration)
	if err != nil {
		return fmt.Errorf("could not parse duration: %w", err)
	}

	expiration := time.Now().UTC().Add(duration)

	request := &v1.CreateApiKeyRequest{
		Expiration: timestamppb.New(expiration),
	}

	response, err := client.CreateApiKey(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot create API key: %w", err)
	}

	return outputResult(response.GetApiKey(), "API Key created", flags.Output)
}

func expireAPIKeyCommand(env *command.Env) error {
	flags := env.Config.(*apiKeyActionFlags)

	if err := RequireString(flags.Prefix, "prefix"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ExpireApiKeyRequest{
		Prefix: flags.Prefix,
	}

	response, err := client.ExpireApiKey(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot expire API key: %w", err)
	}

	return outputResult(response, "API Key expired", flags.Output)
}

func deleteAPIKeyCommand(env *command.Env) error {
	flags := env.Config.(*apiKeyActionFlags)

	if err := RequireString(flags.Prefix, "prefix"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.DeleteApiKeyRequest{
		Prefix: flags.Prefix,
	}

	response, err := client.DeleteApiKey(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot delete API key: %w", err)
	}

	return outputResult(response, "API Key deleted", flags.Output)
}

// API key command definitions

func apiKeyCommands() []*command.C {
	return []*command.C{
		{
			Name:  "api-keys",
			Usage: "<subcommand> [flags] [args...]",
			Help:  "Manage API keys",
			Commands: []*command.C{
				{
					Name:     "list",
					Usage:    "",
					Help:     "List API keys",
					SetFlags: Flags(flax.MustBind, &listAPIKeyFlags{}),
					Run:      listAPIKeysCommand,
				},
				{
					Name:     "ls",
					Usage:    "",
					Help:     "List API keys (alias)",
					SetFlags: Flags(flax.MustBind, &listAPIKeyFlags{}),
					Run:      listAPIKeysCommand,
					Unlisted: true,
				},
				{
					Name:     "create",
					Usage:    "[--expiration <duration>]",
					Help:     "Create a new API key",
					SetFlags: Flags(flax.MustBind, &createAPIKeyFlags{}),
					Run:      createAPIKeyCommand,
				},
				{
					Name:     "expire",
					Usage:    "--prefix <prefix>",
					Help:     "Expire an API key",
					SetFlags: Flags(flax.MustBind, &apiKeyActionFlags{}),
					Run:      expireAPIKeyCommand,
				},
				{
					Name:     "delete",
					Usage:    "--prefix <prefix>",
					Help:     "Delete an API key",
					SetFlags: Flags(flax.MustBind, &apiKeyActionFlags{}),
					Run:      deleteAPIKeyCommand,
				},
			},
		},
		// API key aliases
		{
			Name:     "apikeys",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage API keys (alias)",
			Commands: apiKeyCommands()[0].Commands,
			Unlisted: true,
		},
		{
			Name:     "api",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage API keys (alias)",
			Commands: apiKeyCommands()[0].Commands,
			Unlisted: true,
		},
	}
}
