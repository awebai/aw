package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskCloseCmd = &cobra.Command{
	Use:   "close <ref> [<ref2> ...]",
	Short: "Close one or more tasks",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTaskClose,
}

func init() {
	taskCloseCmd.Flags().String("reason", "", "Reason for closing (stored in notes)")
	taskCmd.AddCommand(taskCloseCmd)
}

type taskCloseOutput struct {
	Closed   []aweb.TaskUpdateResponse `json:"closed"`
	Failures []taskCloseFailure        `json:"failures,omitempty"`
}

type taskCloseFailure struct {
	Ref   string `json:"ref"`
	Error string `json:"error"`
}

func runTaskClose(cmd *cobra.Command, args []string) error {
	reason, _ := cmd.Flags().GetString("reason")

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var result taskCloseOutput

	for _, ref := range args {
		status := "closed"
		req := &aweb.TaskUpdateRequest{Status: &status}
		if reason != "" {
			req.Notes = &reason
		}

		resp, err := client.TaskUpdate(ctx, ref, req)
		if err != nil {
			result.Failures = append(result.Failures, taskCloseFailure{Ref: ref, Error: err.Error()})
			continue
		}
		result.Closed = append(result.Closed, *resp)
	}

	printOutput(result, func(v any) string {
		r := v.(taskCloseOutput)
		var sb fmt.Stringer = &closeFormatter{r}
		return sb.String()
	})

	if len(result.Failures) > 0 {
		return fmt.Errorf("failed to close %d of %d tasks", len(result.Failures), len(args))
	}
	return nil
}

type closeFormatter struct {
	r taskCloseOutput
}

func (f *closeFormatter) String() string {
	var s string
	for _, closed := range f.r.Closed {
		s += fmt.Sprintf("✓ Closed %s: %s\n", closed.TaskRef, closed.Title)
		for _, ac := range closed.AutoClosed {
			s += fmt.Sprintf("  ✓ Auto-closed %s: %s\n", ac.TaskRef, ac.Title)
		}
	}
	for _, fail := range f.r.Failures {
		s += fmt.Sprintf("✗ Failed to close %s: %s\n", fail.Ref, fail.Error)
	}
	return s
}
