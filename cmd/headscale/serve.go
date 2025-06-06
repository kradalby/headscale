package main

import (
	"fmt"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

// Serve and config command flag structures

type serveFlags struct {
	globalFlags
}

type configTestFlags struct {
	globalFlags
}

type versionFlags struct {
	globalFlags
}

// Serve and config command implementations

func serveCommand(env *command.Env) error {
	flags := env.Config.(*serveFlags)

	server, err := newHeadscaleServerWithConfig(flags.Config)
	if err != nil {
		return fmt.Errorf("failed to create server: %w", err)
	}

	return server.Serve()
}

func configTestCommand(env *command.Env) error {
	flags := env.Config.(*configTestFlags)

	_, err := newHeadscaleServerWithConfig(flags.Config)
	if err != nil {
		return fmt.Errorf("configuration test failed: %w", err)
	}

	fmt.Println("Configuration is valid")
	return nil
}

func versionCommand(env *command.Env) error {
	flags := env.Config.(*versionFlags)

	versionInfo := map[string]string{
		"version": "dev", // This should be replaced with actual version info
		"commit":  "unknown",
		"date":    "unknown",
	}

	return outputResult(versionInfo, "Version", flags.Output)
}

// Serve and config command definitions

func serveCommands() []*command.C {
	return []*command.C{
		{
			Name:     "serve",
			Usage:    "",
			Help:     "Start the headscale server",
			SetFlags: Flags(flax.MustBind, &serveFlags{}),
			Run:      serveCommand,
		},
		{
			Name:     "version",
			Usage:    "",
			Help:     "Show version information",
			SetFlags: Flags(flax.MustBind, &versionFlags{}),
			Run:      versionCommand,
		},
	}
}

func configCommands() []*command.C {
	return []*command.C{
		{
			Name:  "config",
			Usage: "test",
			Help:  "Configuration management commands",
			Commands: []*command.C{
				{
					Name:     "test",
					Usage:    "",
					Help:     "Test the configuration file",
					SetFlags: Flags(flax.MustBind, &configTestFlags{}),
					Run:      configTestCommand,
				},
			},
		},
	}
}
