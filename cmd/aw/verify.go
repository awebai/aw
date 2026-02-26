package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
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
	verifyEmail     string
	verifyCode      string
	verifyServerURL string
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
	verifyCmd.Flags().StringVar(&verifyServerURL, "server-url", "", "Base URL for the aweb server (resolved from config if omitted)")

	rootCmd.AddCommand(verifyCmd)
}

func runVerify(cmd *cobra.Command, args []string) error {
	code := strings.TrimSpace(verifyCode)
	if code == "" {
		fmt.Fprintln(os.Stderr, "Missing verification code (use --code)")
		os.Exit(2)
	}

	email := strings.TrimSpace(verifyEmail)
	serverURL := strings.TrimSpace(verifyServerURL)
	var apiKey string
	var sel *awconfig.Selection

	// Always attempt to load config — even when email and server-url are
	// provided via flags, the API key and agent alias are needed for
	// identity provisioning after verification.
	cfg, loadErr := awconfig.LoadGlobal()
	if loadErr != nil && email == "" {
		fatal(fmt.Errorf("failed to load config: %w (use --email to specify directly)", loadErr))
	}
	if loadErr == nil {
		wd, _ := os.Getwd()
		resolved, selErr := awconfig.Resolve(cfg, awconfig.ResolveOptions{
			ServerName:        serverFlag,
			AccountName:       accountFlag,
			ClientName:        "aw",
			WorkingDir:        wd,
			AllowEnvOverrides: true,
		})
		if selErr != nil && (email == "" || serverURL == "") {
			fatal(fmt.Errorf("failed to resolve account: %w (use --email and --server-url to specify directly)", selErr))
		}
		if selErr == nil {
			sel = resolved
			if email == "" {
				email = sel.Email
			}
			if serverURL == "" {
				serverURL = sel.BaseURL
			}
			apiKey = sel.APIKey
		}
	}

	if email == "" {
		fmt.Fprintln(os.Stderr, "Missing email (use --email, or configure an account with an email field)")
		os.Exit(2)
	}

	if serverURL == "" {
		fmt.Fprintln(os.Stderr, "Missing server URL (use --server-url, or configure a default account)")
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

	// Provision self-custody identity so the register→verify→whoami flow
	// produces a working DID. If a keypair exists in config, use it;
	// otherwise generate a fresh one.
	if apiKey != "" {
		claimIdentityAfterVerify(baseURL, apiKey, sel)
	}

	return nil
}

// claimIdentityAfterVerify ensures the agent has a self-custody identity
// registered on the server after email verification succeeds.
func claimIdentityAfterVerify(baseURL, apiKey string, sel *awconfig.Selection) {
	cfgPath := mustDefaultGlobalPath()
	keysDir := awconfig.KeysDir(cfgPath)

	var pub ed25519.PublicKey
	var did, signingKeyPath string
	var needConfigUpdate bool
	custody := aweb.CustodySelf
	lifetime := aweb.LifetimePersistent
	generatedNewKey := false

	if sel != nil && sel.DID != "" && sel.SigningKey != "" {
		// Config already has identity fields; load the existing key.
		loadedPriv, loadErr := awconfig.LoadSigningKey(sel.SigningKey)
		if loadErr != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not load signing key %s: %v\n", sel.SigningKey, loadErr)
			return
		}
		pub = loadedPriv.Public().(ed25519.PublicKey)
		did = sel.DID
		signingKeyPath = sel.SigningKey
	} else {
		// No identity in config — generate a fresh keypair.
		var alias string
		if sel != nil {
			alias = sel.AgentAlias
		}
		if alias == "" {
			fmt.Fprintln(os.Stderr, "Warning: cannot provision identity — no agent alias in config.")
			return
		}
		var nsSlug string
		if sel != nil {
			nsSlug = sel.NamespaceSlug
		}

		address := deriveAgentAddress(nsSlug, "", alias)
		signingKeyPath = awconfig.SigningKeyPath(keysDir, address)

		// Reuse existing key on disk if present.
		existingPriv, loadErr := awconfig.LoadSigningKey(signingKeyPath)
		if loadErr == nil {
			pub = existingPriv.Public().(ed25519.PublicKey)
		} else {
			genPub, genPriv, genErr := awconfig.GenerateKeypair()
			if genErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: keypair generation failed: %v\n", genErr)
				return
			}
			if err := awconfig.SaveKeypair(keysDir, address, genPub, genPriv); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not save keypair: %v\n", err)
				return
			}
			pub = genPub
			generatedNewKey = true
		}
		did = aweb.ComputeDIDKey(pub)
		needConfigUpdate = true
	}

	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)
	authClient, err := aweb.NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not create authenticated client: %v\n", err)
		return
	}

	claimCtx, claimCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer claimCancel()

	_, claimErr := authClient.ClaimIdentity(claimCtx, &aweb.ClaimIdentityRequest{
		DID:       did,
		PublicKey: pubKeyB64,
		Custody:   aweb.CustodySelf,
		Lifetime:  aweb.LifetimePersistent,
	})
	if claimErr != nil {
		claimCode, ok := aweb.HTTPStatusCode(claimErr)
		if ok && claimCode == 409 {
			var address string
			if sel != nil {
				address = deriveAgentAddress(sel.NamespaceSlug, "", sel.AgentAlias)
			}
			if address == "" {
				fatal(fmt.Errorf("identity already set on server (409) but cannot derive address for recovery; run 'aw reset --remote --confirm'"))
			}
			// Remove orphan key if we just generated it — it doesn't match
			// the server's identity.
			if generatedNewKey {
				os.Remove(signingKeyPath)
				pubPath := strings.TrimSuffix(signingKeyPath, ".key") + ".pub"
				os.Remove(pubPath)
			}
			var recoveredCustody, recoveredLifetime string
			did, signingKeyPath, recoveredCustody, recoveredLifetime = recoverIdentity409(claimCtx, authClient, keysDir, address)
			if recoveredCustody != "" {
				custody = recoveredCustody
			}
			if recoveredLifetime != "" {
				lifetime = recoveredLifetime
			}
			needConfigUpdate = true
		} else if ok && claimCode == 404 {
			fmt.Fprintln(os.Stderr, "Warning: server does not support identity claim (404). Signed messaging not available.")
			return
		} else {
			fatal(fmt.Errorf("identity claim failed: %w", claimErr))
		}
	}

	// Persist identity to config. ClawDID registration is deferred to
	// aw connect or aw register (which have richer context for the handle).
	if needConfigUpdate {
		if sel == nil || sel.AccountName == "" {
			fmt.Fprintln(os.Stderr, "Warning: identity claimed but no account in config to update. Run 'aw connect' to persist.")
		} else {
			updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
				acct := cfg.Accounts[sel.AccountName]
				acct.DID = did
				acct.SigningKey = signingKeyPath
				acct.Custody = custody
				acct.Lifetime = lifetime
				cfg.Accounts[sel.AccountName] = acct
				return nil
			})
			if updateErr != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not update config with identity: %v\n", updateErr)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Identity: %s\n", did)
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
