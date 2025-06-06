package main

import (
	"fmt"
	"strconv"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
)

// Node command flags
var nodeArgs struct {
	ID       uint64 `flag:"id,i,Node ID"`
	User     string `flag:"user,u,User identifier (ID, username, email, or provider ID)"`
	ShowTags bool   `flag:"show-tags,Show tags in output"`
	Tags     string `flag:"tags,t,Comma-separated tags"`
	Routes   string `flag:"routes,r,Comma-separated routes"`
	Key      string `flag:"key,k,Registration key"`
	NewName  string `flag:"new-name,New node name"`
}

// Node command implementations

func registerNodeCommand(env *command.Env) error {
	if err := requireString(nodeArgs.User, "user"); err != nil {
		return err
	}
	if err := requireString(nodeArgs.Key, "key"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.RegisterNodeRequest{
		Key:  nodeArgs.Key,
		User: nodeArgs.User,
	}

	response, err := client.RegisterNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot register node: %w", err)
	}

	return outputResult(
		response.GetNode(),
		fmt.Sprintf("Node %s registered", response.GetNode().GetGivenName()),
		globalArgs.Output,
	)
}

func listNodesCommand(env *command.Env) error {
	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ListNodesRequest{}

	// If user is specified, use it directly as string
	if nodeArgs.User != "" {
		request.User = nodeArgs.User
	}

	response, err := client.ListNodes(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot get nodes: %w", err)
	}

	if globalArgs.Output != "" {
		return outputResult(response.GetNodes(), "Nodes", globalArgs.Output)
	}

	tableData, err := nodesToPtables(nodeArgs.User, nodeArgs.ShowTags, response.GetNodes())
	if err != nil {
		return fmt.Errorf("error converting to table: %w", err)
	}

	return outputResult(tableData, "Nodes", "table")
}

func expireNodeCommand(env *command.Env) error {
	if err := requireUint64(nodeArgs.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ExpireNodeRequest{NodeId: nodeArgs.ID}

	response, err := client.ExpireNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot expire node: %w", err)
	}

	return outputResult(response.GetNode(), "Node expired", globalArgs.Output)
}

func renameNodeCommand(env *command.Env, newName string) error {
	if err := requireUint64(nodeArgs.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.RenameNodeRequest{
		NodeId:  nodeArgs.ID,
		NewName: newName,
	}

	response, err := client.RenameNode(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot rename node: %w", err)
	}

	return outputResult(response.GetNode(), "Node renamed", globalArgs.Output)
}

func deleteNodeCommand(env *command.Env) error {
	if err := requireUint64(nodeArgs.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Get node first for confirmation
	getRequest := &v1.GetNodeRequest{NodeId: nodeArgs.ID}
	getResponse, err := client.GetNode(ctx, getRequest)
	if err != nil {
		return fmt.Errorf("error getting node: %w", err)
	}

	if !globalArgs.Force {
		// TODO: Add confirmation prompt
		fmt.Printf("This will delete node %s (ID: %d). Use --force to skip this confirmation.\n",
			getResponse.GetNode().GetName(), nodeArgs.ID)
		return fmt.Errorf("deletion cancelled")
	}

	deleteRequest := &v1.DeleteNodeRequest{NodeId: nodeArgs.ID}
	response, err := client.DeleteNode(ctx, deleteRequest)
	if err != nil {
		return fmt.Errorf("error deleting node: %w", err)
	}

	if globalArgs.Output != "" {
		return outputResult(response, "Node deleted", globalArgs.Output)
	}

	fmt.Printf("Node %s deleted successfully\n", getResponse.GetNode().GetName())
	return nil
}

func moveNodeCommand(env *command.Env) error {
	if err := requireUint64(nodeArgs.ID, "id"); err != nil {
		return err
	}
	if err := requireString(nodeArgs.User, "user"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Try to resolve user identifier to ID
	userID, err := ResolveUserToID(ctx, client, nodeArgs.User)
	if err != nil {
		// Fallback: try parsing as direct uint64 for backwards compatibility
		if parsedID, parseErr := strconv.ParseUint(nodeArgs.User, 10, 64); parseErr == nil {
			userID = parsedID
		} else {
			return fmt.Errorf("cannot resolve user identifier '%s': %w", nodeArgs.User, err)
		}
	}

	request := &v1.MoveNodeRequest{
		NodeId: nodeArgs.ID,
		User:   userID,
	}

	response, err := client.MoveNode(ctx, request)
	if err != nil {
		return fmt.Errorf("error moving node: %w", err)
	}

	return outputResult(response.GetNode(), "Node moved to another user", globalArgs.Output)
}

func setNodeTagsCommand(env *command.Env) error {
	if err := requireUint64(nodeArgs.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.SetTagsRequest{
		NodeId: nodeArgs.ID,
		Tags:   parseCommaSeparated(nodeArgs.Tags),
	}

	response, err := client.SetTags(ctx, request)
	if err != nil {
		return fmt.Errorf("error setting tags: %w", err)
	}

	return outputResult(response.GetNode(), "Node tags updated", globalArgs.Output)
}

func listNodeRoutesCommand(env *command.Env) error {
	if err := requireUint64(nodeArgs.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Get the node first to access its routes
	request := &v1.GetNodeRequest{NodeId: nodeArgs.ID}
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

	return outputResult(routes, "Node Routes", globalArgs.Output)
}

func approveNodeRoutesCommand(env *command.Env) error {
	if err := requireUint64(nodeArgs.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.SetApprovedRoutesRequest{
		NodeId: nodeArgs.ID,
		Routes: parseCommaSeparated(nodeArgs.Routes),
	}

	response, err := client.SetApprovedRoutes(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot approve routes: %w", err)
	}

	return outputResult(response.GetNode(), "Routes approved", globalArgs.Output)
}

func backfillNodeIPsCommand(env *command.Env) error {
	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(globalArgs.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.BackfillNodeIPsRequest{
		Confirmed: globalArgs.Force,
	}

	response, err := client.BackfillNodeIPs(ctx, request)
	if err != nil {
		return fmt.Errorf("cannot backfill node IPs: %w", err)
	}

	return outputResult(response.GetChanges(), "Node IPs backfilled", globalArgs.Output)
}

// Node command definitions

func nodeCommands() []*command.C {
	return []*command.C{
		{
			Name:     "nodes",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage nodes in Headscale",
			SetFlags: command.Flags(flax.MustBind, &nodeArgs),
			Commands: []*command.C{
				{
					Name:  "register",
					Usage: "--user <user> --key <key>",
					Help:  "Register a new node",
					Run:   registerNodeCommand,
				},
				{
					Name:  "list",
					Usage: "[--user <user>] [flags]",
					Help:  "List nodes",
					Run:   listNodesCommand,
				},
				{
					Name:     "ls",
					Usage:    "[--user <user>] [flags]",
					Help:     "List nodes (alias)",
					Run:      listNodesCommand,
					Unlisted: true,
				},
				{
					Name:  "expire",
					Usage: "--id <id>",
					Help:  "Expire a node",
					Run:   expireNodeCommand,
				},
				{
					Name:  "rename",
					Usage: "--id <id> <new-name>",
					Help:  "Rename a node",
					Run:   command.Adapt(renameNodeCommand),
				},
				{
					Name:  "delete",
					Usage: "--id <id>",
					Help:  "Delete a node",
					Run:   deleteNodeCommand,
				},
				{
					Name:     "destroy",
					Usage:    "--id <id>",
					Help:     "Delete a node (alias)",
					Run:      deleteNodeCommand,
					Unlisted: true,
				},
				{
					Name:  "move",
					Usage: "--id <id> --user <user>",
					Help:  "Move a node to another user",
					Run:   moveNodeCommand,
				},
				{
					Name:  "tags",
					Usage: "--id <id> --tags <tag1,tag2,...>",
					Help:  "Set tags for a node",
					Run:   setNodeTagsCommand,
				},
				{
					Name:  "routes",
					Usage: "<subcommand> [flags]",
					Help:  "Manage node routes",
					Commands: []*command.C{
						{
							Name:  "list",
							Usage: "--id <id>",
							Help:  "List routes for a node",
							Run:   listNodeRoutesCommand,
						},
						{
							Name:  "approve",
							Usage: "--id <id> --routes <route1,route2,...>",
							Help:  "Approve routes for a node",
							Run:   approveNodeRoutesCommand,
						},
					},
				},
				{
					Name:  "backfill-ips",
					Usage: "",
					Help:  "Backfill node IPs",
					Run:   backfillNodeIPsCommand,
				},
			},
		},
		// Node management alias
		{
			Name:     "node",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage nodes in Headscale (alias)",
			SetFlags: command.Flags(flax.MustBind, &nodeArgs),
			Commands: []*command.C{
				{
					Name:  "register",
					Usage: "--user <user> --key <key>",
					Help:  "Register a new node",
					Run:   registerNodeCommand,
				},
				{
					Name:  "list",
					Usage: "[--user <user>] [flags]",
					Help:  "List nodes",
					Run:   listNodesCommand,
				},
				{
					Name:  "expire",
					Usage: "--id <id>",
					Help:  "Expire a node",
					Run:   expireNodeCommand,
				},
				{
					Name:  "rename",
					Usage: "--id <id> <new-name>",
					Help:  "Rename a node",
					Run:   command.Adapt(renameNodeCommand),
				},
				{
					Name:  "delete",
					Usage: "--id <id>",
					Help:  "Delete a node",
					Run:   deleteNodeCommand,
				},
				{
					Name:  "move",
					Usage: "--id <id> --user <user>",
					Help:  "Move a node to another user",
					Run:   moveNodeCommand,
				},
				{
					Name:  "tags",
					Usage: "--id <id> --tags <tag1,tag2,...>",
					Help:  "Set tags for a node",
					Run:   setNodeTagsCommand,
				},
				{
					Name:  "routes",
					Usage: "<subcommand> [flags]",
					Help:  "Manage node routes",
					Commands: []*command.C{
						{
							Name:  "list",
							Usage: "--id <id>",
							Help:  "List routes for a node",
							Run:   listNodeRoutesCommand,
						},
						{
							Name:  "approve",
							Usage: "--id <id> --routes <route1,route2,...>",
							Help:  "Approve routes for a node",
							Run:   approveNodeRoutesCommand,
						},
					},
				},
				{
					Name:  "backfill-ips",
					Usage: "",
					Help:  "Backfill node IPs",
					Run:   backfillNodeIPsCommand,
				},
			},
			Unlisted: true,
		},
	}
}
