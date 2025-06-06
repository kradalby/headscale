package commands

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/creachadair/command"
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
	ID   uint64   `flag:"id,i,Node ID (required)"`
	Tags []string `flag:"tags,t,Comma-separated tags"`
}

type nodeRouteFlags struct {
	globalFlags
	ID     uint64   `flag:"id,i,Node ID (required)"`
	Routes []string `flag:"routes,r,Comma-separated routes"`
}

// Node command implementations
func registerNodeCommand(env *command.Env) error {
	flags := env.Config.(*registerNodeFlags)

	userID, err := validateUserReference(flags.userFlags)
	if err != nil {
		return err
	}
	if err := requireString(flags.Key, "key"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.RegisterNodeRequest{
		UserId: userID,
		Key:    flags.Key,
	}

	response, err := client.RegisterNode(ctx, request)
	if err != nil {
		return err
	}

	return outputResult(response.Node, "Node registered", flags.Output)
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
	if flags.User != "" {
		userID, err := validateUserReference(flags.userFlags)
		if err != nil {
			return err
		}
		request.UserId = userID
	}

	response, err := client.ListNodes(ctx, request)
	if err != nil {
		return err
	}

	if len(response.Nodes) == 0 {
		return outputResult([]string{}, "No nodes found", flags.Output)
	}

	return outputResult(response.Nodes, "", flags.Output)
}

func expireNodeCommand(env *command.Env) error {
	flags := env.Config.(*nodeActionFlags)

	if err := requireUint64(flags.ID, "id"); err != nil {
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
		return err
	}

	return outputResult(response.Node, "Node expired", flags.Output)
}

func renameNodeCommand(env *command.Env, newName string) error {
	flags := env.Config.(*nodeActionFlags)

	if err := requireUint64(flags.ID, "id"); err != nil {
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
		return err
	}

	return outputResult(response.Node, "Node renamed", flags.Output)
}

func deleteNodeCommand(env *command.Env) error {
	flags := env.Config.(*nodeActionFlags)

	if err := requireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// Get node info for confirmation
	listReq := &v1.ListNodesRequest{}
	listResp, err := client.ListNodes(ctx, listReq)
	if err != nil {
		return err
	}

	var targetNode *v1.Node
	for _, node := range listResp.Nodes {
		if node.Id == flags.ID {
			targetNode = node
			break
		}
	}

	if targetNode == nil {
		return fmt.Errorf("node with ID %d not found", flags.ID)
	}

	// Confirm deletion if not forced
	if !flags.Force {
		prompt := &survey.Confirm{
			Message: fmt.Sprintf("Are you sure you want to delete node '%s'?", targetNode.Name),
		}
		var confirm bool
		if err := survey.AskOne(prompt, &confirm); err != nil {
			return err
		}
		if !confirm {
			return fmt.Errorf("node deletion cancelled")
		}
	}

	request := &v1.DeleteNodeRequest{NodeId: flags.ID}
	_, err = client.DeleteNode(ctx, request)
	if err != nil {
		return err
	}

	return outputResult(map[string]string{
		"message": fmt.Sprintf("Node '%s' deleted", targetNode.Name),
	}, "Node deleted", flags.Output)
}

func moveNodeCommand(env *command.Env) error {
	flags := env.Config.(*nodeActionFlags)

	if err := requireUint64(flags.ID, "id"); err != nil {
		return err
	}
	if err := requireString(flags.User, "user"); err != nil {
		return err
	}

	// Resolve the target user ID
	userID, err := resolveUserID(flags.User)
	if err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.MoveNodeRequest{
		NodeId: flags.ID,
		UserId: userID,
	}

	response, err := client.MoveNode(ctx, request)
	if err != nil {
		return err
	}

	return outputResult(response.Node, "Node moved", flags.Output)
}

func setNodeTagsCommand(env *command.Env) error {
	flags := env.Config.(*nodeTagFlags)

	if err := requireUint64(flags.ID, "id"); err != nil {
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
		return err
	}

	return outputResult(response.Node, "Node tags updated", flags.Output)
}

func listNodeRoutesCommand(env *command.Env) error {
	flags := env.Config.(*nodeRouteFlags)

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	request := &v1.ListNodesRequest{}
	if flags.ID != 0 {
		request.NodeId = flags.ID
	}

	response, err := client.ListNodes(ctx, request)
	if err != nil {
		return err
	}

	routes := make([]map[string]interface{}, 0)
	for _, node := range response.Nodes {
		if flags.ID != 0 && node.Id != flags.ID {
			continue
		}
		for _, route := range node.ForcedTags {
			routes = append(routes, map[string]interface{}{
				"node_id":   node.Id,
				"node_name": node.Name,
				"route":     route,
				"enabled":   true, // TODO: Get actual route status
			})
		}
	}

	return outputResult(routes, "Node routes", flags.Output)
}

func approveNodeRoutesCommand(env *command.Env) error {
	flags := env.Config.(*nodeRouteFlags)

	if err := requireUint64(flags.ID, "id"); err != nil {
		return err
	}

	ctx, client, conn, cancel, err := newHeadscaleCLIWithConfig(flags.Config)
	if err != nil {
		return err
	}
	defer cancel()
	defer conn.Close()

	// TODO: Implement route approval when API is available
	return fmt.Errorf("route approval not yet implemented")
}

func backfillNodeIPsCommand(env *command.Env) error {
	flags := env.Config.(*globalFlags)

	confirm := false
	if !flags.Force {
		prompt := &survey.Confirm{
			Message: "Are you sure that you want to assign/remove IPs to/from nodes?",
		}
		err := survey.AskOne(prompt, &confirm)
		if err != nil {
			return err
		}
		if !confirm {
			return fmt.Errorf("operation cancelled")
		}
	}

	// TODO: Implement IP backfill when API is available
	return fmt.Errorf("IP backfill not yet implemented")
}

// NodeCommands returns the node management command tree
func NodeCommands() []*command.C {
	nodeCommands := []*command.C{
		{
			Name:     "register",
			Usage:    "--user <user> --key <key>",
			Help:     "Register a node to your network",
			SetFlags: setFlags(&registerNodeFlags{}),
			Run:      registerNodeCommand,
		},
		{
			Name:     "list",
			Usage:    "[flags]",
			Help:     "List nodes",
			SetFlags: setFlags(&listNodeFlags{}),
			Run:      listNodesCommand,
		},
		{
			Name:     "ls",
			Usage:    "[flags]",
			Help:     "List nodes (alias)",
			SetFlags: setFlags(&listNodeFlags{}),
			Run:      listNodesCommand,
			Unlisted: true,
		},
		{
			Name:     "expire",
			Usage:    "--id <id>",
			Help:     "Expire (log out) a node",
			SetFlags: setFlags(&nodeActionFlags{}),
			Run:      expireNodeCommand,
		},
		{
			Name:     "logout",
			Usage:    "--id <id>",
			Help:     "Expire (log out) a node (alias)",
			SetFlags: setFlags(&nodeActionFlags{}),
			Run:      expireNodeCommand,
			Unlisted: true,
		},
		{
			Name:     "rename",
			Usage:    "--id <id> <new-name>",
			Help:     "Rename a node",
			SetFlags: setFlags(&nodeActionFlags{}),
			Run:      command.Adapt(renameNodeCommand),
		},
		{
			Name:     "delete",
			Usage:    "--id <id>",
			Help:     "Delete a node",
			SetFlags: setFlags(&nodeActionFlags{}),
			Run:      deleteNodeCommand,
		},
		{
			Name:     "del",
			Usage:    "--id <id>",
			Help:     "Delete a node (alias)",
			SetFlags: setFlags(&nodeActionFlags{}),
			Run:      deleteNodeCommand,
			Unlisted: true,
		},
		{
			Name:     "move",
			Usage:    "--id <id> --user <user>",
			Help:     "Move node to another user",
			SetFlags: setFlags(&nodeActionFlags{}),
			Run:      moveNodeCommand,
		},
		{
			Name:  "tags",
			Usage: "set --id <id> --tags <tags>",
			Help:  "Manage node tags",
			Commands: []*command.C{
				{
					Name:     "set",
					Usage:    "--id <id> --tags <tags>",
					Help:     "Set tags for a node",
					SetFlags: setFlags(&nodeTagFlags{}),
					Run:      setNodeTagsCommand,
				},
			},
		},
		{
			Name:  "routes",
			Usage: "<subcommand> [flags]",
			Help:  "Manage node routes",
			Commands: []*command.C{
				{
					Name:     "list",
					Usage:    "[--id <id>]",
					Help:     "List routes available on nodes",
					SetFlags: setFlags(&nodeRouteFlags{}),
					Run:      listNodeRoutesCommand,
				},
				{
					Name:     "approve",
					Usage:    "--id <id> --routes <routes>",
					Help:     "Approve routes for a node",
					SetFlags: setFlags(&nodeRouteFlags{}),
					Run:      approveNodeRoutesCommand,
				},
			},
		},
		{
			Name:     "backfill-ips",
			Usage:    "",
			Help:     "Backfill missing IPs for nodes",
			SetFlags: setFlags(&globalFlags{}),
			Run:      backfillNodeIPsCommand,
		},
	}

	return []*command.C{
		// Main nodes command
		{
			Name:     "nodes",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage nodes in Headscale",
			Commands: nodeCommands,
		},

		// Node aliases
		{
			Name:     "node",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage nodes in Headscale (alias)",
			Commands: nodeCommands,
			Unlisted: true,
		},
		{
			Name:     "machine",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage nodes in Headscale (alias)",
			Commands: nodeCommands,
			Unlisted: true,
		},
		{
			Name:     "machines",
			Usage:    "<subcommand> [flags] [args...]",
			Help:     "Manage nodes in Headscale (alias)",
			Commands: nodeCommands,
			Unlisted: true,
		},
	}
}
