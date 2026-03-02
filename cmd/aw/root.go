package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var serverFlag string
var accountFlag string
var debugFlag bool
var jsonFlag bool

var rootCmd = &cobra.Command{
	Use:   "aw",
	Short: "aweb CLI",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if !debugFlag && os.Getenv("AW_DEBUG") == "1" {
			debugFlag = true
		}
		loadDotenvBestEffort()
	},
	SilenceUsage:  true,
	SilenceErrors: true,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// No-op: version command doesn't require command initialization side-effects.
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
	rootCmd.PersistentFlags().BoolVar(&jsonFlag, "json", false, "Output as JSON")
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(upgradeCmd)
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		msg := err.Error()
		if hint := checkVerificationRequired(err); hint != "" {
			msg = hint
		}
		fmt.Fprintln(os.Stderr, msg)
		os.Exit(exitCode(err))
	}
}
