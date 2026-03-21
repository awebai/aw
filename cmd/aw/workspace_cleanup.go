package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
)

type goneWorkspace struct {
	WorkspaceID   string
	Alias         string
	WorkspacePath string
}

// detectGoneWorkspaces checks for workspaces on this hostname whose paths
// no longer exist, and soft-deletes them on the server.
func detectGoneWorkspaces(client *aweb.Client, selfWorkspaceID string) []goneWorkspace {
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.WorkspaceList(ctx, aweb.WorkspaceListParams{
		Hostname:        hostname,
		IncludePresence: false,
	})
	if err != nil {
		return nil
	}

	var gone []goneWorkspace
	deleted := map[string]bool{}

	for _, ws := range resp.Workspaces {
		path := derefString(ws.WorkspacePath)
		if path == "" || ws.WorkspaceID == selfWorkspaceID {
			continue
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			continue
		}
		if deleted[ws.WorkspaceID] {
			continue
		}

		deleteCtx, deleteCancel := context.WithTimeout(context.Background(), 5*time.Second)
		deleteErr := client.WorkspaceDelete(deleteCtx, ws.WorkspaceID)
		deleteCancel()
		if deleteErr != nil {
			continue
		}
		deleted[ws.WorkspaceID] = true
		gone = append(gone, goneWorkspace{
			WorkspaceID:   ws.WorkspaceID,
			Alias:         ws.Alias,
			WorkspacePath: path,
		})
	}

	return gone
}

func formatGoneWorkspaces(gone []goneWorkspace) string {
	if len(gone) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("Cleaned up gone workspaces:\n")
	for _, g := range gone {
		sb.WriteString(fmt.Sprintf("  %s (%s)\n", g.Alias, abbreviateUserHome(g.WorkspacePath)))
	}
	return sb.String()
}
