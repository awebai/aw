package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var serverFlag string
var accountFlag string
var debugFlag bool

var rootCmd = &cobra.Command{
	Use:   "aw",
	Short: "aweb CLI",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !debugFlag && os.Getenv("AW_DEBUG") == "1" {
			debugFlag = true
		}
		loadDotenvBestEffort()
		go fireHeartbeat()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// No heartbeat for version.
	},
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("aw %s\n", version)
		if commit != "none" {
			fmt.Printf("  commit: %s\n", commit)
		}
		if date != "unknown" {
			fmt.Printf("  built:  %s\n", date)
		}
		checkLatestVersion(os.Stdout, "")
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&serverFlag, "server-name", "", "Server name from config.yaml")
	rootCmd.PersistentFlags().StringVar(&accountFlag, "account", "", "Account name from config.yaml")
	rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "Log background errors to stderr")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(updateCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
