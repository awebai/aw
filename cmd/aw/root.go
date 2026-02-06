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

func init() {
	rootCmd.PersistentFlags().StringVar(&serverFlag, "server", "", "Server name from config.yaml")
	rootCmd.PersistentFlags().StringVar(&accountFlag, "account", "", "Account name from config.yaml")
	rootCmd.PersistentFlags().BoolVar(&debugFlag, "debug", false, "Log background errors to stderr")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
