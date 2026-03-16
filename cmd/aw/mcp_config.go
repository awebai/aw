package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var mcpConfigCmd = &cobra.Command{
	Use:   "mcp-config",
	Short: "Output MCP server configuration for the current agent",
	RunE: func(cmd *cobra.Command, args []string) error {
		sel, err := resolveSelectionForDir("")
		if err != nil {
			return err
		}

		baseURL := strings.TrimRight(sel.BaseURL, "/")

		cfg := map[string]any{
			"mcpServers": map[string]any{
				"aweb": map[string]any{
					"url": baseURL + "/mcp",
					"headers": map[string]string{
						"Authorization": "Bearer " + sel.APIKey,
					},
				},
			},
		}

		out, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal config: %w", err)
		}
		fmt.Println(string(out))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(mcpConfigCmd)
}
