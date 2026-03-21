package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskCmd = &cobra.Command{
	Use:   "task",
	Short: "Manage tasks",
}

func init() {
	rootCmd.AddCommand(taskCmd)
}

// --- Shared formatting ---

func taskPriorityIcon(p int) string {
	if p <= 2 {
		return "●"
	}
	return "○"
}

func formatTaskLine(t aweb.TaskSummary) string {
	icon := taskPriorityIcon(t.Priority)
	return fmt.Sprintf("%s %s [%s P%d] [%s] - %s",
		icon, t.TaskRef, icon, t.Priority, t.TaskType, t.Title)
}

func formatTaskDetail(t *aweb.Task) string {
	var sb strings.Builder

	icon := taskPriorityIcon(t.Priority)
	statusLabel := strings.ToUpper(t.Status)
	sb.WriteString(fmt.Sprintf("%s %s · %s   [%s P%d · %s]\n",
		icon, t.TaskRef, t.Title, icon, t.Priority, statusLabel))
	sb.WriteString(fmt.Sprintf("Type: %s\n", t.TaskType))
	sb.WriteString(fmt.Sprintf("Created: %s · Updated: %s\n", taskFormatDate(t.CreatedAt), taskFormatDate(t.UpdatedAt)))

	if t.Description != "" {
		sb.WriteString(fmt.Sprintf("\nDESCRIPTION\n%s\n", t.Description))
	}

	if t.Notes != "" {
		sb.WriteString(fmt.Sprintf("\nNOTES\n%s\n", t.Notes))
	}

	if len(t.BlockedBy) > 0 {
		sb.WriteString("\nBLOCKED BY\n")
		for _, dep := range t.BlockedBy {
			sb.WriteString(fmt.Sprintf("  → ○ %s: %s [%s]\n", dep.TaskRef, dep.Title, dep.Status))
		}
	}

	if len(t.Blocks) > 0 {
		sb.WriteString("\nBLOCKS\n")
		for _, dep := range t.Blocks {
			sb.WriteString(fmt.Sprintf("  ← ○ %s: %s [%s]\n", dep.TaskRef, dep.Title, dep.Status))
		}
	}

	return sb.String()
}

func taskFormatDate(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return ts
	}
	return t.Format("2006-01-02")
}

// parsePriority parses a priority string, stripping P/p prefix.
// Returns the priority value and an error if invalid.
func parsePriority(raw string) (int, error) {
	p := strings.TrimPrefix(strings.TrimPrefix(raw, "P"), "p")
	pv, err := strconv.Atoi(p)
	if err != nil || pv < 0 || pv > 4 {
		return 0, fmt.Errorf("invalid priority %q — use a number 0-4 (e.g., --priority 2 or --priority P2)", raw)
	}
	return pv, nil
}
