package main

import (
	"fmt"
	"os"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Manage workspace roles",
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available roles from the project policy",
	RunE:  runRolesList,
}

var rolesSetCmd = &cobra.Command{
	Use:   "set [role]",
	Short: "Set the current workspace's role",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRolesSet,
}

func init() {
	rolesCmd.AddCommand(rolesListCmd)
	rolesCmd.AddCommand(rolesSetCmd)
	rootCmd.AddCommand(rolesCmd)
	rolesCmd.GroupID = groupCoordination
}

func runRolesList(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	roles, err := fetchWorkspacePolicyRoles(client)
	if err != nil {
		return err
	}

	if len(roles) == 0 {
		fmt.Println("No roles defined in the active project policy.")
		return nil
	}

	if jsonFlag {
		printJSON(roles)
		return nil
	}

	for i, role := range roles {
		fmt.Printf("  %d. %s\n", i+1, role)
	}
	return nil
}

func runRolesSet(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	requested := ""
	if len(args) > 0 {
		requested = strings.TrimSpace(args[0])
	}

	role, err := resolveAndValidateRole(client, requested)
	if err != nil {
		return err
	}

	wd, _ := os.Getwd()
	_, err = autoAttachContext(wd, client, role)
	if err != nil {
		return fmt.Errorf("setting role: %w", err)
	}
	fmt.Printf("Role set to %s\n", role)
	return nil
}

// resolveAndValidateRole resolves a role against the project policy.
// This is the single entry point for role validation across all flows.
// If requested is empty and TTY is available, prompts with numbered choices.
// If requested is empty and not TTY, errors with the available roles list.
func resolveAndValidateRole(client *aweb.Client, requested string) (string, error) {
	roles, err := fetchWorkspacePolicyRoles(client)
	if err != nil {
		// Policy endpoint not available — accept the requested role as-is.
		debugLog("fetch roles for validation: %v", err)
		if requested != "" {
			return normalizeWorkspaceRole(requested), nil
		}
		return "", nil
	}

	if len(roles) > 0 {
		return selectRoleFromAvailableRoles(requested, roles, isTTY() && requested == "", os.Stdin, os.Stderr)
	}

	// No policy — accept whatever is provided.
	return normalizeWorkspaceRole(requested), nil
}
