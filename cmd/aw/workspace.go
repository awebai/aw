package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Manage repo-local coordination workspaces",
}

var workspaceInitCmd = &cobra.Command{
	Use:    "init",
	Short:  "Register the current git worktree for coordination",
	Hidden: true,
	RunE:   runWorkspaceInit,
}

var workspaceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show coordination status for the current agent/context and team",
	RunE:  runWorkspaceStatus,
}

var (
	workspaceInitRole       string
	workspaceInitRepoOrigin string
	workspaceStatusLimit    int
)

type workspaceInitOutput struct {
	WorkspaceID     string `json:"workspace_id"`
	ProjectID       string `json:"project_id"`
	ProjectSlug     string `json:"project_slug"`
	RepoID          string `json:"repo_id"`
	CanonicalOrigin string `json:"canonical_origin"`
	Alias           string `json:"alias"`
	HumanName       string `json:"human_name"`
	Role            string `json:"role,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	WorkspacePath   string `json:"workspace_path,omitempty"`
	Created         bool   `json:"created"`
}

type workspaceStatusOutput struct {
	Workspace          aweb.WorkspaceInfo                `json:"workspace"`
	ContextKind        string                            `json:"context_kind"`
	Locks              []aweb.ReservationView            `json:"locks,omitempty"`
	Team               []aweb.WorkspaceInfo              `json:"team,omitempty"`
	TeamLocks          map[string][]aweb.ReservationView `json:"team_locks,omitempty"`
	EscalationsPending int                               `json:"escalations_pending"`
	ConflictCount      int                               `json:"conflict_count"`
}

func init() {
	workspaceInitCmd.Flags().StringVar(&workspaceInitRole, "role", "", "Coordination role for this workspace")
	workspaceInitCmd.Flags().StringVar(&workspaceInitRepoOrigin, "repo-origin", "", "Override git remote origin URL")

	workspaceStatusCmd.Flags().IntVar(&workspaceStatusLimit, "limit", 15, "Maximum team workspaces to show")

	workspaceCmd.AddCommand(workspaceInitCmd)
	workspaceCmd.AddCommand(workspaceStatusCmd)
	rootCmd.AddCommand(workspaceCmd)
}

func runWorkspaceInit(cmd *cobra.Command, args []string) error {
	loadDotenvBestEffort()

	root, err := currentGitWorktreeRoot()
	if err != nil {
		return usageError("workspace init requires a git worktree")
	}

	client, sel, err := resolveClientSelectionForDir(root)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sel.AgentID) == "" || strings.TrimSpace(sel.AgentAlias) == "" {
		return usageError("selected account has no agent identity; run 'aw init' first")
	}

	out, err := registerWorkspaceForRoot(root, client, strings.TrimSpace(workspaceInitRole), strings.TrimSpace(workspaceInitRepoOrigin))
	if err != nil {
		return err
	}
	printOutput(*out, formatWorkspaceInit)
	return nil
}

func runWorkspaceStatus(cmd *cobra.Command, args []string) error {
	loadDotenvBestEffort()

	workingDir, _ := os.Getwd()
	client, sel, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sel.AgentID) == "" {
		return usageError("selected account has no agent identity; run 'aw init' first")
	}

	state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("load workspace state: %w", err)
	}

	workspaceID := strings.TrimSpace(sel.AgentID)
	if state != nil && strings.TrimSpace(state.WorkspaceID) != "" {
		workspaceID = strings.TrimSpace(state.WorkspaceID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	teamResp, err := client.WorkspaceTeam(ctx, aweb.WorkspaceTeamParams{
		IncludeClaims:            true,
		IncludePresence:          true,
		OnlyWithClaims:           false,
		AlwaysIncludeWorkspaceID: workspaceID,
		Limit:                    workspaceStatusLimit,
	})
	if err != nil {
		return err
	}

	locksResp, err := client.ReservationList(ctx, "")
	if err != nil {
		return err
	}

	statusResp, err := client.CoordinationStatus(ctx, "")
	if err != nil {
		return err
	}

	locksByWorkspace := map[string][]aweb.ReservationView{}
	for _, reservation := range locksResp.Reservations {
		holder := strings.TrimSpace(reservation.HolderAgentID)
		if holder == "" {
			continue
		}
		locksByWorkspace[holder] = append(locksByWorkspace[holder], reservation)
	}
	for holder := range locksByWorkspace {
		sort.Slice(locksByWorkspace[holder], func(i, j int) bool {
			return locksByWorkspace[holder][i].ResourceKey < locksByWorkspace[holder][j].ResourceKey
		})
	}

	var self aweb.WorkspaceInfo
	team := make([]aweb.WorkspaceInfo, 0, len(teamResp.Workspaces))
	for _, workspace := range teamResp.Workspaces {
		if workspace.WorkspaceID == workspaceID {
			self = workspace
			continue
		}
		team = append(team, workspace)
	}

	if self.WorkspaceID == "" {
		self = fallbackWorkspaceInfo(sel, state)
	}

	teamLocks := map[string][]aweb.ReservationView{}
	for _, workspace := range team {
		if locks := locksByWorkspace[workspace.WorkspaceID]; len(locks) > 0 {
			teamLocks[workspace.WorkspaceID] = locks
		}
	}

	printOutput(workspaceStatusOutput{
		Workspace:          self,
		ContextKind:        inferWorkspaceContextKind(self, state),
		Locks:              locksByWorkspace[workspaceID],
		Team:               team,
		TeamLocks:          teamLocks,
		EscalationsPending: statusResp.EscalationsPending,
		ConflictCount:      len(statusResp.Conflicts),
	}, formatWorkspaceStatus)
	return nil
}

func currentGitWorktreeRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return currentGitWorktreeRootFromDir(wd)
}

func currentGitWorktreeRootFromDir(workingDir string) (string, error) {
	cmd := exec.Command("git", "-C", workingDir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", fmt.Errorf("git returned empty worktree root")
	}
	return root, nil
}

type contextAttachResult struct {
	Workspace   *workspaceInitOutput
	ContextKind string
}

func autoAttachContext(workingDir string, client *aweb.Client) (*contextAttachResult, error) {
	root, err := currentGitWorktreeRootFromDir(workingDir)
	if err != nil {
		return registerLocalAttachmentForDir(workingDir, client)
	}

	origin, err := resolveWorkspaceRepoOrigin(root, "")
	if err != nil {
		return registerLocalAttachmentForDir(workingDir, client)
	}

	out, err := registerWorkspaceForRoot(root, client, "", origin)
	if err != nil {
		return nil, err
	}
	return &contextAttachResult{
		Workspace:   out,
		ContextKind: "repo_worktree",
	}, nil
}

func registerWorkspaceForRoot(root string, client *aweb.Client, roleOverride string, repoOrigin string) (*workspaceInitOutput, error) {
	origin, err := resolveWorkspaceRepoOrigin(root, repoOrigin)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()

	statePath := filepath.Join(root, awconfig.DefaultWorktreeWorkspaceRelativePath())
	existingState, err := awconfig.LoadWorktreeWorkspaceFrom(statePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", statePath, err)
	}

	role := strings.TrimSpace(roleOverride)
	if role == "" && existingState != nil {
		role = strings.TrimSpace(existingState.Role)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.WorkspaceRegister(ctx, &aweb.WorkspaceRegisterRequest{
		RepoOrigin:    origin,
		Role:          role,
		Hostname:      hostname,
		WorkspacePath: root,
	})
	if err != nil {
		return nil, err
	}

	state := &awconfig.WorktreeWorkspace{
		WorkspaceID:     resp.WorkspaceID,
		ProjectID:       resp.ProjectID,
		ProjectSlug:     resp.ProjectSlug,
		RepoID:          resp.RepoID,
		CanonicalOrigin: resp.CanonicalOrigin,
		Alias:           resp.Alias,
		HumanName:       resp.HumanName,
		Role:            role,
		Hostname:        hostname,
		WorkspacePath:   root,
		UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(statePath, state); err != nil {
		return nil, fmt.Errorf("write %s: %w", statePath, err)
	}

	return &workspaceInitOutput{
		WorkspaceID:     resp.WorkspaceID,
		ProjectID:       resp.ProjectID,
		ProjectSlug:     resp.ProjectSlug,
		RepoID:          resp.RepoID,
		CanonicalOrigin: resp.CanonicalOrigin,
		Alias:           resp.Alias,
		HumanName:       resp.HumanName,
		Role:            role,
		Hostname:        hostname,
		WorkspacePath:   root,
		Created:         resp.Created,
	}, nil
}

func registerLocalAttachmentForDir(workingDir string, client *aweb.Client) (*contextAttachResult, error) {
	hostname, _ := os.Hostname()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.WorkspaceAttach(ctx, &aweb.WorkspaceAttachRequest{
		AttachmentType: "local_dir",
		Hostname:       hostname,
	})
	if err != nil {
		return nil, err
	}

	if err := clearLocalWorkspaceState(workingDir); err != nil {
		return nil, err
	}

	return &contextAttachResult{
		ContextKind: "local_dir",
		Workspace: &workspaceInitOutput{
			WorkspaceID: resp.WorkspaceID,
			ProjectID:   resp.ProjectID,
			ProjectSlug: resp.ProjectSlug,
			Alias:       resp.Alias,
			HumanName:   resp.HumanName,
			Hostname:    hostname,
			Created:     resp.Created,
		},
	}, nil
}

func clearLocalWorkspaceState(workingDir string) error {
	statePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := os.Remove(statePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove %s: %w", statePath, err)
	}
	return nil
}

func resolveWorkspaceRepoOrigin(root, explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	cmd := exec.Command("git", "-C", root, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return "", usageError("missing git remote origin; use --repo-origin to register this workspace")
	}
	origin := strings.TrimSpace(string(out))
	if origin == "" {
		return "", usageError("missing git remote origin; use --repo-origin to register this workspace")
	}
	return origin, nil
}

func fallbackWorkspaceInfo(sel *awconfig.Selection, state *awconfig.WorktreeWorkspace) aweb.WorkspaceInfo {
	info := aweb.WorkspaceInfo{
		WorkspaceID: sel.AgentID,
		Alias:       sel.AgentAlias,
		Status:      "offline",
	}
	if state == nil {
		return info
	}
	if strings.TrimSpace(state.WorkspaceID) != "" {
		info.WorkspaceID = strings.TrimSpace(state.WorkspaceID)
	}
	if strings.TrimSpace(state.Alias) != "" {
		info.Alias = strings.TrimSpace(state.Alias)
	}
	if strings.TrimSpace(state.HumanName) != "" {
		info.HumanName = stringPtr(strings.TrimSpace(state.HumanName))
	}
	if strings.TrimSpace(state.ProjectID) != "" {
		info.ProjectID = stringPtr(strings.TrimSpace(state.ProjectID))
	}
	if strings.TrimSpace(state.ProjectSlug) != "" {
		info.ProjectSlug = stringPtr(strings.TrimSpace(state.ProjectSlug))
	}
	if strings.TrimSpace(state.Role) != "" {
		info.Role = stringPtr(strings.TrimSpace(state.Role))
	}
	if strings.TrimSpace(state.Hostname) != "" {
		info.Hostname = stringPtr(strings.TrimSpace(state.Hostname))
	}
	if strings.TrimSpace(state.WorkspacePath) != "" {
		info.WorkspacePath = stringPtr(strings.TrimSpace(state.WorkspacePath))
	}
	if strings.TrimSpace(state.CanonicalOrigin) != "" {
		info.Repo = stringPtr(strings.TrimSpace(state.CanonicalOrigin))
	}
	return info
}

func inferWorkspaceContextKind(info aweb.WorkspaceInfo, state *awconfig.WorktreeWorkspace) string {
	if kind := derefString(info.ContextKind); kind != "" {
		return kind
	}
	if state != nil {
		if strings.TrimSpace(state.CanonicalOrigin) != "" || strings.TrimSpace(state.WorkspacePath) != "" {
			return "repo_worktree"
		}
	}
	if derefString(info.Repo) != "" || derefString(info.Branch) != "" || derefString(info.WorkspacePath) != "" {
		return "repo_worktree"
	}
	return "none"
}

func stringPtr(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &v
}

func formatWorkspaceInit(v any) string {
	out := v.(workspaceInitOutput)
	var sb strings.Builder
	action := "Updated"
	if out.Created {
		action = "Registered"
	}
	sb.WriteString(fmt.Sprintf("%s workspace %s\n", action, out.Alias))
	sb.WriteString(fmt.Sprintf("Workspace ID: %s\n", out.WorkspaceID))
	sb.WriteString(fmt.Sprintf("Namespace:    %s\n", out.ProjectSlug))
	sb.WriteString(fmt.Sprintf("Repo:         %s\n", out.CanonicalOrigin))
	if out.Role != "" {
		sb.WriteString(fmt.Sprintf("Role:         %s\n", out.Role))
	}
	if out.WorkspacePath != "" {
		sb.WriteString(fmt.Sprintf("Path:         %s\n", abbreviateUserHome(out.WorkspacePath)))
	}
	return sb.String()
}

func formatWorkspaceStatus(v any) string {
	out := v.(workspaceStatusOutput)
	var sb strings.Builder

	sb.WriteString("## Self\n")
	sb.WriteString(fmt.Sprintf("- Alias: %s\n", out.Workspace.Alias))
	sb.WriteString(fmt.Sprintf("- Context: %s\n", out.ContextKind))
	if out.Workspace.Role != nil && strings.TrimSpace(*out.Workspace.Role) != "" {
		sb.WriteString(fmt.Sprintf("- Role: %s\n", strings.TrimSpace(*out.Workspace.Role)))
	}
	sb.WriteString(fmt.Sprintf("- Status: %s\n", out.Workspace.Status))
	if out.Workspace.Hostname != nil && strings.TrimSpace(*out.Workspace.Hostname) != "" {
		sb.WriteString(fmt.Sprintf("- Hostname: %s\n", strings.TrimSpace(*out.Workspace.Hostname)))
	}
	if out.Workspace.WorkspacePath != nil && strings.TrimSpace(*out.Workspace.WorkspacePath) != "" {
		sb.WriteString(fmt.Sprintf("- Path: %s\n", abbreviateUserHome(strings.TrimSpace(*out.Workspace.WorkspacePath))))
	}
	if out.Workspace.Repo != nil && strings.TrimSpace(*out.Workspace.Repo) != "" {
		sb.WriteString(fmt.Sprintf("- Repo: %s\n", strings.TrimSpace(*out.Workspace.Repo)))
	}
	if out.Workspace.Branch != nil && strings.TrimSpace(*out.Workspace.Branch) != "" {
		sb.WriteString(fmt.Sprintf("- Branch: %s\n", strings.TrimSpace(*out.Workspace.Branch)))
	}

	if len(out.Workspace.Claims) > 0 {
		sb.WriteString("\n## Claims\n")
		for _, claim := range out.Workspace.Claims {
			title := ""
			if claim.Title != nil && strings.TrimSpace(*claim.Title) != "" {
				title = fmt.Sprintf(" \"%s\"", strings.TrimSpace(*claim.Title))
			}
			sb.WriteString(fmt.Sprintf("- %s%s — %s\n", claim.BeadID, title, formatTimeAgo(claim.ClaimedAt)))
		}
	}

	if len(out.Locks) > 0 {
		sb.WriteString("\n## Locks\n")
		now := time.Now()
		for _, lock := range out.Locks {
			sb.WriteString(fmt.Sprintf("- %s — expires in %s\n", lock.ResourceKey, formatDuration(ttlRemainingSeconds(lock.ExpiresAt, now))))
		}
	}

	sb.WriteString("\n## Team\n")
	if len(out.Team) == 0 {
		sb.WriteString("No other workspaces.\n")
	} else {
		for _, workspace := range out.Team {
			line := fmt.Sprintf("- %s", workspace.Alias)
			if workspace.Role != nil && strings.TrimSpace(*workspace.Role) != "" {
				line += " (" + strings.TrimSpace(*workspace.Role) + ")"
			}
			line += " — " + workspace.Status
			if len(workspace.Claims) > 0 {
				line += fmt.Sprintf(", %d claim(s)", len(workspace.Claims))
			}
			if lastSeen := derefString(workspace.LastSeen); lastSeen != "" {
				line += ", seen " + formatTimeAgo(lastSeen)
			}
			sb.WriteString(line + "\n")
			for _, claim := range workspace.Claims {
				title := ""
				if claim.Title != nil && strings.TrimSpace(*claim.Title) != "" {
					title = fmt.Sprintf(" \"%s\"", strings.TrimSpace(*claim.Title))
				}
				sb.WriteString(fmt.Sprintf("  %s%s\n", claim.BeadID, title))
			}
			for _, lock := range out.TeamLocks[workspace.WorkspaceID] {
				sb.WriteString(fmt.Sprintf("  lock %s\n", lock.ResourceKey))
			}
		}
	}

	sb.WriteString(fmt.Sprintf("\nEscalations pending: %d\n", out.EscalationsPending))
	if out.ConflictCount > 0 {
		sb.WriteString(fmt.Sprintf("Claim conflicts: %d\n", out.ConflictCount))
	}
	return sb.String()
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func abbreviateUserHome(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	home = filepath.Clean(home)
	path = filepath.Clean(path)
	if path == home {
		return "~"
	}
	prefix := home + string(filepath.Separator)
	if strings.HasPrefix(path, prefix) {
		return "~" + string(filepath.Separator) + strings.TrimPrefix(path, prefix)
	}
	return path
}
