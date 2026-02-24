package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var connectSetDefault bool

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Connect to an aweb server using environment credentials",
	Long: `Reads AWEB_URL and AWEB_API_KEY from the environment (or .env.aweb),
validates them via introspect, and writes persistent config so future
commands work without environment variables.`,
	RunE: runConnect,
}

func init() {
	connectCmd.Flags().BoolVar(&connectSetDefault, "set-default", false, "Set this account as default even if one already exists")
	rootCmd.AddCommand(connectCmd)
}

func runConnect(cmd *cobra.Command, args []string) error {
	baseURL := strings.TrimSpace(os.Getenv("AWEB_URL"))
	apiKey := strings.TrimSpace(os.Getenv("AWEB_API_KEY"))

	if baseURL == "" {
		fmt.Fprintln(os.Stderr, "AWEB_URL is not set. Create a .env.aweb file with AWEB_URL and AWEB_API_KEY, or export them.")
		os.Exit(2)
	}
	if apiKey == "" {
		fmt.Fprintln(os.Stderr, "AWEB_API_KEY is not set. Create a .env.aweb file with AWEB_URL and AWEB_API_KEY, or export them.")
		os.Exit(2)
	}

	baseURL, err := resolveWorkingBaseURL(baseURL)
	if err != nil {
		fatal(err)
	}

	serverName, _ := awconfig.DeriveServerNameFromURL(baseURL)

	client, err := aweb.NewWithAPIKey(baseURL, apiKey)
	if err != nil {
		fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := client.Introspect(ctx)
	if err != nil {
		fatal(err)
	}

	if strings.TrimSpace(resp.AgentID) == "" {
		fmt.Fprintln(os.Stderr, "This API key is not agent-scoped (no agent_id). Use an agent-scoped key from the dashboard.")
		os.Exit(2)
	}

	// Fetch namespace slug for canonical address derivation (needed for
	// self-custody signing and key file naming).
	var namespaceSlug string
	proj, projErr := client.GetCurrentProject(ctx)
	if projErr == nil {
		namespaceSlug = strings.TrimSpace(proj.Slug)
	}

	alias := strings.TrimSpace(resp.Alias)
	agentID := strings.TrimSpace(resp.AgentID)

	// Derive account name from server + agent_id (stable across alias changes).
	accountName := "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(agentID)

	cfgPath := mustDefaultGlobalPath()
	keysDir := awconfig.KeysDir(cfgPath)

	// Check existing config for identity fields before provisioning.
	existingCfg, _ := awconfig.LoadGlobalFrom(cfgPath)
	var existingDID, existingSigningKey, existingStableID, existingCustody, existingLifetime string
	if existingCfg != nil {
		for _, acct := range existingCfg.Accounts {
			if strings.TrimSpace(acct.AgentID) == agentID && strings.TrimSpace(acct.Server) == serverName {
				existingDID = strings.TrimSpace(acct.DID)
				existingSigningKey = strings.TrimSpace(acct.SigningKey)
				existingStableID = strings.TrimSpace(acct.StableID)
				existingCustody = strings.TrimSpace(acct.Custody)
				existingLifetime = strings.TrimSpace(acct.Lifetime)
				break
			}
		}
	}

	// Provision identity if not already present.
	identityDID := existingDID
	signingKeyPath := existingSigningKey
	stableID := existingStableID
	custody := existingCustody
	lifetime := existingLifetime
	if existingDID == "" || existingSigningKey == "" {
		identityDID, signingKeyPath, stableID, custody, lifetime = provisionIdentity(
			ctx, client, cfgPath, keysDir, baseURL, namespaceSlug, alias,
		)
	}

	updateErr := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
		if cfg.Servers == nil {
			cfg.Servers = map[string]awconfig.Server{}
		}
		if cfg.Accounts == nil {
			cfg.Accounts = map[string]awconfig.Account{}
		}

		// Check for existing account with same server+agent_id — update it.
		for name, acct := range cfg.Accounts {
			if strings.TrimSpace(acct.AgentID) == agentID && strings.TrimSpace(acct.Server) == serverName {
				accountName = name
				break
			}
		}

		cfg.Servers[serverName] = awconfig.Server{URL: baseURL}

		cfg.Accounts[accountName] = awconfig.Account{
			Server:        serverName,
			APIKey:        apiKey,
			AgentID:       agentID,
			AgentAlias:    alias,
			NamespaceSlug: namespaceSlug,
			DID:           identityDID,
			StableID:      stableID,
			SigningKey:    signingKeyPath,
			Custody:       custody,
			Lifetime:      lifetime,
		}

		if strings.TrimSpace(cfg.DefaultAccount) == "" || connectSetDefault {
			cfg.DefaultAccount = accountName
		}
		return nil
	})
	if updateErr != nil {
		fatal(updateErr)
	}

	if err := writeOrUpdateContext(serverName, accountName); err != nil {
		fatal(err)
	}

	fmt.Fprintf(os.Stderr, "Connected as %s (%s)\n", alias, agentID)
	if identityDID != "" {
		fmt.Fprintf(os.Stderr, "Identity: %s (%s)\n", identityDID, custody)
	}
	if stableID != "" {
		fmt.Fprintf(os.Stderr, "Stable ID: %s\n", stableID)
	}
	fmt.Fprintf(os.Stderr, "Config written to %s\n", cfgPath)

	// Print introspect output as JSON for scriptability.
	printJSON(resp)

	return nil
}

// provisionIdentity generates a keypair, claims identity on the server, and
// optionally registers with ClawDID. Returns the identity fields to persist.
func provisionIdentity(
	ctx context.Context,
	client *aweb.Client,
	cfgPath, keysDir, baseURL, namespaceSlug, alias string,
) (did, signingKeyPath, stableID, custody, lifetime string) {
	pub, priv, err := awconfig.GenerateKeypair()
	if err != nil {
		fatal(err)
	}

	did = aweb.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	// Persist the keypair to disk BEFORE claiming on the server.
	// If claim succeeds but disk write fails later, the key would be
	// unrecoverable. An unused key file on disk is harmless.
	address := deriveAgentAddress(namespaceSlug, "", alias)
	if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
		fatal(err)
	}
	signingKeyPath = awconfig.SigningKeyPath(keysDir, address)

	// Claim identity on the aweb server.
	_, err = client.ClaimIdentity(ctx, &aweb.ClaimIdentityRequest{
		DID:       did,
		PublicKey: pubKeyB64,
		Custody:   "self",
		Lifetime:  "persistent",
	})
	if err != nil {
		code, ok := aweb.HTTPStatusCode(err)
		if ok && code == 409 {
			fmt.Fprintln(os.Stderr, "Identity already set on server. If you have the signing key, add signing_key to your account config manually.")
			os.Exit(1)
		}
		fatal(err)
	}

	custody = "self"
	lifetime = "persistent"

	// Resolve ClawDID registry URL.
	registryURL := strings.TrimSpace(os.Getenv("CLAWDID_REGISTRY_URL"))
	if registryURL == "" {
		existCfg, loadErr := awconfig.LoadGlobalFrom(cfgPath)
		if loadErr == nil && strings.TrimSpace(existCfg.ClawDIDRegistryURL) != "" {
			registryURL = strings.TrimSpace(existCfg.ClawDIDRegistryURL)
		}
	}
	if registryURL == "" {
		registryURL = awconfig.DefaultClawDIDRegistryURL
	}

	// Best-effort ClawDID registration.
	stableID = registerClawDID(ctx, registryURL, pub, priv, did, baseURL, address)

	return did, signingKeyPath, stableID, custody, lifetime
}

// registerClawDID attempts to register the agent's stable_id with ClawDID.
// Returns the stable_id on success, or empty string on failure.
func registerClawDID(
	ctx context.Context,
	registryURL string,
	pub ed25519.PublicKey, priv ed25519.PrivateKey,
	did, serverURL, address string,
) string {
	didClaw := aweb.ComputeStableID(pub, "claw")
	stateHash := aweb.ComputeStateHash(didClaw, did, serverURL, address, nil)
	timestamp := time.Now().UTC().Format(time.RFC3339)

	entry := aweb.LogEntry{
		AuthorizedBy:   did,
		DIDClaw:        didClaw,
		NewDIDKey:      did,
		Operation:      "create",
		PrevEntryHash:  nil,
		PreviousDIDKey: nil,
		Seq:            1,
		StateHash:      stateHash,
		Timestamp:      timestamp,
	}
	canonical := entry.CanonicalJSON()
	sig := ed25519.Sign(priv, []byte(canonical))
	proof := base64.RawStdEncoding.EncodeToString(sig)

	clawDIDClient := &aweb.ClawDIDClient{RegistryURL: registryURL}
	_, err := clawDIDClient.Register(ctx, &aweb.ClawDIDRegisterRequest{
		DIDClaw:      didClaw,
		DIDKey:       did,
		Server:       serverURL,
		Address:      address,
		Seq:          1,
		StateHash:    stateHash,
		AuthorizedBy: did,
		Timestamp:    timestamp,
		Proof:        proof,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: ClawDID registration failed (non-fatal): %v\n", err)
		return ""
	}

	return didClaw
}
