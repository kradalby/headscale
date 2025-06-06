package main

import (
	"fmt"
	"strconv"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Node command flag structures

type listNodeFlags struct {
	globalFlags
	userFlags
	ShowTags bool `flag:"show-tags,Show tags in output"`
}

type registerNodeFlags struct {
	globalFlags
	userFlags
	Key string `flag:"key,k,Registration key (required)"`
}

type nodeActionFlags struct {
	globalFlags
	ID   uint64 `flag:"id,i,Node ID (required)"`
	User string `flag:"user,u,User identifier (for move command)"`
	Name string `flag:"name,New node name (for rename command)"`
}

type nodeTagFlags struct {
	globalFlags
	tagsFlags
	ID uint64 `flag:"id,i,Node ID (required)"`
}

type nodeRouteFlags struct {
	globalFlags
	routesFlags
	ID uint64 `flag:"id,i,Node ID (required)"`
}

// Node command implementations

func registerNodeCommand(env *command.Env) error {
	flags := env.Config.(*registerNodeFlags)

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

	// For now, we'll use the user string directly since the API expects a string

	request := &v1.RegisterNodeRequest{
		Key:  flags.Key,
		User: flags.User, // Use the original user string
	}

	response, err := client.RegisterNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot register node: %w", err)
	}

	return outputResult(
		response.GetNode(),
		fmt.Sprintf("Node %s registered", response.GetNode().GetGivenName()),
		flags.Output,
	)
}

func listNodesCommand(env *command.Env) error {
	flags := env.Config.(*listNodeFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ListNodesRequest{}

	// If user is specified, use it directly as string
	if flags.User != "" {
		request.User = flags.User
	}

	response, err := client.ListNodes(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot get nodes: %w", err)
	}

	if flags.Output != "" {
		return outputResult(response.GetNodes(), "Nodes", flags.Output)
	}

	tableData, err := nodesToPtables(flags.User, flags.ShowTags, response.GetNodes())
	if err != nil {
		return fmt.Errorf("error converting to table: %w", err)
	}

	return outputResult(tableData, "Nodes", "table")
}

func expireNodeCommand(env *command.Env) error {
	flags := env.Config.(*nodeActionFlags)

	if err := RequireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ExpireNodeRequest{NodeId: flags.ID}

	response, err := client.ExpireNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot expire node: %w", err)
	}

	return outputResult(response.GetNode(), "Node expired", flags.Output)
}

func renameNodeCommand(env *command.Env, newName string) error {
	flags := env.Config.(*nodeActionFlags)

	if err := RequireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.RenameNodeRequest{
		NodeId:  flags.ID,
		NewName: newName,
	}

	response, err := client.RenameNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot rename node: %w", err)
	}

	return outputResult(response.GetNode(), "Node renamed", flags.Output)
}

func deleteNodeCommand(env *command.Env) error {
	flags := env.Config.(*nodeActionFlags)

	if err := RequireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Get node first for confirmation
	getRequest := &v1.GetNodeRequest{NodeId: flags.ID}
	getResponse, err := client.GetNode(ctx, getRequest)
	if err != nil {
		return fmt.Errorf("error getting node: %w", err)
	}

	if !flags.Force {
		// TODO: Add confirmation prompt
		fmt.Printf("This will delete node %s (ID: %d). Use --force to skip this confirmation.\n",
			getResponse.GetNode().GetName(), flags.ID)
		return fmt.Errorf("deletion cancelled")
	}

	deleteRequest := &v1.DeleteNodeRequest{NodeId: flags.ID}
	response, err := client.DeleteNode(ctx, deleteRequest)
	if err != nil {
		return fmt.Errorf("error deleting node: %w", err)
	}

	if flags.Output != "" {
		return outputResult(response, "Node deleted", flags.Output)
	}

	fmt.Printf("Node %s deleted successfully\n", getResponse.GetNode().GetName())
	return nil
}

func moveNodeCommand(env *command.Env) error {
	flags := env.Config.(*nodeActionFlags)

	if err := RequireUint64(flags.ID, "id"); err != nil {
		return err
	}
	if err := RequireString(flags.User, "user"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Parse user as uint64 for the API
	userID, err := strconv.ParseUint(flags.User, 10, 64)
	if err != nil {
		return fmt.Errorf("user must be a numeric ID for move operation: %w", err)
	}

	request := &v1.MoveNodeRequest{
		NodeId: flags.ID,
		User:   userID,
	}

	response, err := client.MoveNode(ctx, request)
	if err != nil {
		return fmt.Errorf("error moving node: %w", err)
	}

	return outputResult(response.GetNode(), "Node moved to another user", flags.Output)
}

func setNodeTagsCommand(env *command.Env) error {
	flags := env.Config.(*nodeTagFlags)

	if err := RequireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.SetTagsRequest{
		NodeId: flags.ID,
		Tags:   flags.Tags,
	}

	response, err := client.SetTags(ctx, request)
	if err != nil {
		return fmt.Errorf("error setting tags: %w", err)
	}

	return outputResult(response.GetNode(), "Node tags updated", flags.Output)
}

func listNodeRoutesCommand(env *command.Env) error {
	flags := env.Config.(*nodeRouteFlags)

	if err := RequireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Get the node first to access its routes
	request := &v1.GetNodeRequest{NodeId: flags.ID}
	response, err := client.GetNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot get node: %w", err)
	}

	node := response.GetNode()
	routes := map[string]interface{}{
		"approved_routes":  node.GetApprovedRoutes(),
		"available_routes": node.GetAvailableRoutes(),
		"subnet_routes":    node.GetSubnetRoutes(),
	}

	return outputResult(routes, "Node Routes", flags.Output)
}

func approveNodeRoutesCommand(env *command.Env) error {
	flags := env.Config.(*nodeRouteFlags)

	if err := RequireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.SetApprovedRoutesRequest{
		NodeId: flags.ID,
		Routes: flags.Routes,
	}

	response, err := client.SetApprovedRoutes(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot approve routes: %w", err)
	}

	return outputResult(response.GetNode(), "Routes approved", flags.Output)
}

func backfillNodeIPsCommand(env *command.Env) error {
	flags := env.Config.(*globalFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.BackfillNodeIPsRequest{
		Confirmed: flags.Force,
	}

	response, err := client.BackfillNodeIPs(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot backfill node IPs: %w", err)
	}

	return outputResult(response.GetChanges(), "Node IPs backfilled", flags.Output)
}

// Node command definitions

func nodeCommands() []*command.C {
	return []*command.C{
		{
			Name:  "nodes",
			Usage: "<subcommand> [flags] [args...]",
			Help:  "Manage nodes in Headscale",
			Commands: []*command.C{
				{
					Name:     "register",
					Usage:    "--user <user> --key <key>",
					Help:     "Register a new node",
					SetFlags: Flags(flax.MustBind, &registerNodeFlags{}),
					Run:      registerNodeCommand,
				},
				{
					Name:     "list",
					Usage:    "[--user <user>] [flags]",
					Help:     "List nodes",
					SetFlags: Flags(flax.MustBind, &listNodeFlags{}),
					Run:      listNodesCommand,
				},
				{
					Name:     "ls",
					Usage:    "[--user <user>] [flags]",
					Help:     "List nodes (alias)",
					SetFlags: Flags(flax.MustBind, &listNodeFlags{}),
					Run:      listNodesCommand,
					Unlisted: true,
				},
				{
					Name:     "expire",
					Usage:    "--id <id>",
					Help:     "Expire a node",
					SetFlags: Flags(flax.MustBind, &nodeActionFlags{}),
					Run:      expireNodeCommand,
				},
				{
					Name:     "rename",
					Usage:    "--id <id> <new-name>",
					Help:     "Rename a node",
					SetFlags: Flags(flax.MustBind, &nodeActionFlags{}),
					Run:      command.Adapt(renameNodeCommand),
				},
				{
					Name:     "delete",
					Usage:    "--id <id>",
					Help:     "Delete a node",
					SetFlags: Flags(flax.MustBind, &nodeActionFlags{}),
					Run:      deleteNodeCommand,
				},
				{
					Name:     "move",
					Usage:    "--id <id> --user <user>",
					Help:     "Move a node to another user",
					SetFlags: Flags(flax.MustBind, &nodeActionFlags{}),
					Run:      moveNodeCommand,
				},
				{
					Name:     "tags",
					Usage:    "--id <id> --tags <tag1,tag2,...>",
					Help:     "Set tags for a node",
					SetFlags: Flags(flax.MustBind, &nodeTagFlags{}),
					Run:      setNodeTagsCommand,
				},
				{
					Name:  "routes",
					Usage: "<subcommand> [flags]",
					Help:  "Manage node routes",
					Commands: []*command.C{
						{
							Name:     "list",
							Usage:    "--id <id>",
							Help:     "List routes for a node",
							SetFlags: Flags(flax.MustBind, &nodeRouteFlags{}),
							Run:      listNodeRoutesCommand,
						},
						{
							Name:     "approve",
							Usage:    "--id <id> --routes <route1,route2,...>",
							Help:     "Approve routes for a node",
							SetFlags: Flags(flax.MustBind, &nodeRouteFlags{}),
							Run:      approveNodeRoutesCommand,
						},
					},
				},
				{
					Name:     "backfill-ips",
					Usage:    "",
					Help:     "Backfill node IPs",
					SetFlags: Flags(flax.MustBind, &globalFlags{}),
					Run:      backfillNodeIPsCommand,
				},
			},
		},
		// Node management aliases
		{
			Name:     "node",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage nodes in Headscale (alias)",
			Commands: nodeCommands()[0].Commands, // Reuse the same subcommands
			Unlisted: true,
		},
	}
}
