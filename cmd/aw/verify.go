package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var (
	verifyEmail string
	verifyCode  string
)

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify email ownership with a 6-digit code",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat — the API key may not be active yet.
	},
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().StringVar(&verifyEmail, "email", "", "Email address to verify (resolved from config if omitted)")
	verifyCmd.Flags().StringVar(&verifyCode, "code", "", "6-digit verification code from email (required)")

	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	code := strings.TrimSpace(verifyCode)
	if code == "" {
		fmt.Fprintln(os.Stderr, "Missing verification code (use --code)")
		os.Exit(2)
	}

	email := strings.TrimSpace(verifyEmail)
	serverURL := strings.TrimSpace(serverFlag)
	var apiKey string

	// Resolve email, server, and API key from config if not fully provided.
	if email == "" || serverURL == "" {
		cfg, loadErr := awconfig.LoadGlobal()
		if loadErr != nil && email == "" {
			fatal(fmt.Errorf("failed to load config: %w (use --email to specify directly)", loadErr))
		}
		if loadErr == nil {
			wd, _ := os.Getwd()
			sel, selErr := awconfig.Resolve(cfg, awconfig.ResolveOptions{
				ServerName:        serverFlag,
				AccountName:       accountFlag,
				WorkingDir:        wd,
				AllowEnvOverrides: true,
			})
			if selErr != nil && (email == "" || serverURL == "") {
				fatal(fmt.Errorf("failed to resolve account: %w (use --email and --server to specify directly)", selErr))
			}
			if selErr == nil {
				if email == "" {
					email = sel.Email
				}
				if serverURL == "" {
					serverURL = sel.BaseURL
				}
				apiKey = sel.APIKey
			}
		}
	}

	if email == "" {
		fmt.Fprintln(os.Stderr, "Missing email (use --email, or configure an account with an email field)")
		os.Exit(2)
	}

	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Missing server (use --server, or configure a default account)")
		os.Exit(2)
	}

	baseURL, err := resolveWorkingBaseURL(serverURL)
	if err != nil {
		fatal(err)
	}

	client, err := aweb.New(baseURL)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := client.VerifyCode(ctx, &aweb.VerifyCodeRequest{
		Email: email,
		Code:  code,
	})
	if err != nil {
		statusCode, isHTTP := aweb.HTTPStatusCode(err)
		if !isHTTP {
			fatal(err)
		}
		switch statusCode {
		case 400:
			body, _ := aweb.HTTPErrorBody(err)
			fatal(formatVerifyError(body))
		case 404:
			fatal(fmt.Errorf("no pending verification found for %s", email))
		case 429:
			fatal(fmt.Errorf("too many verification attempts. Please try again later"))
		default:
			fatal(err)
		}
	}

	if !resp.Verified {
		fatal(fmt.Errorf("verification failed"))
	}

	fmt.Println("Verified!")

	// Fire a heartbeat to confirm the API key is now active.
	if apiKey != "" {
		hbClient, hbErr := aweb.NewWithAPIKey(baseURL, apiKey)
		if hbErr == nil {
			hbCtx, hbCancel := context.WithTimeout(context.Background(), 5*time.Second)
			_, hbErr = hbClient.Heartbeat(hbCtx)
			hbCancel()
			if hbErr == nil {
				fmt.Println("Your agent is now active.")
			} else {
				fmt.Fprintf(os.Stderr, "Warning: heartbeat failed after verification: %v\n", hbErr)
			}
		}
	}

	return nil
}

// formatVerifyError parses structured error bodies from the verify-code endpoint.
func formatVerifyError(body string) error {
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err == nil && envelope.Error.Message != "" {
		return fmt.Errorf("%s", envelope.Error.Message)
	}
	if strings.TrimSpace(body) != "" {
		return fmt.Errorf("verification failed: %s", body)
	}
	return fmt.Errorf("verification failed")
}
