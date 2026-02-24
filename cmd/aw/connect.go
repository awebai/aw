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
		// Preserve existing stable_id if provisioning didn't produce one
		// (e.g. 409 recovery or ClawDID failure).
		if stableID == "" && existingStableID != "" {
			stableID = existingStableID
		}
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
	address := deriveAgentAddress(namespaceSlug, "", alias)
	signingKeyPath = awconfig.SigningKeyPath(keysDir, address)

	// Reuse existing key if one is already on disk for this address,
	// to avoid overwriting a valid key before we know whether the server
	// accepts our claim.
	var pub ed25519.PublicKey
	var priv ed25519.PrivateKey
	generatedNewKey := false
	existingPriv, loadErr := awconfig.LoadSigningKey(signingKeyPath)
	if loadErr == nil {
		priv = existingPriv
		pub = priv.Public().(ed25519.PublicKey)
	} else {
		var genErr error
		pub, priv, genErr = awconfig.GenerateKeypair()
		if genErr != nil {
			fatal(genErr)
		}
		// Persist the keypair to disk BEFORE claiming on the server.
		// If claim succeeds but disk write fails later, the key would be
		// unrecoverable. An unused key file on disk is harmless.
		if err := awconfig.SaveKeypair(keysDir, address, pub, priv); err != nil {
			fatal(err)
		}
		generatedNewKey = true
	}

	did = aweb.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	// Claim identity on the aweb server.
	_, err := client.ClaimIdentity(ctx, &aweb.ClaimIdentityRequest{
		DID:       did,
		PublicKey: pubKeyB64,
		Custody:   "self",
		Lifetime:  "persistent",
	})
	if err != nil {
		code, ok := aweb.HTTPStatusCode(err)
		if ok && code == 409 {
			// Remove orphan key if we just generated it — it doesn't match
			// the server's identity and would be confusing on disk.
			if generatedNewKey {
				os.Remove(signingKeyPath)
				pubPath := strings.TrimSuffix(signingKeyPath, ".key") + ".pub"
				os.Remove(pubPath)
			}
			recoveredDID, recoveredKeyPath, recoveredCustody, recoveredLifetime := recoverIdentity409(ctx, client, keysDir, address)
			return recoveredDID, recoveredKeyPath, stableID, recoveredCustody, recoveredLifetime
		}
		fatal(err)
	}

	custody = "self"
	lifetime = "persistent"

	// ClawDID expects canonical server origin (scheme+host), not the API
	// base URL which may include a path like /api.
	serverOrigin := canonicalOrigin(baseURL)

	// Best-effort ClawDID registration.
	stableID = registerClawDIDWithHandle(ctx, resolveClawDIDRegistryURL(cfgPath), pub, priv, did, serverOrigin, address, nil)

	return did, signingKeyPath, stableID, custody, lifetime
}

// recoverIdentity409 handles a 409 from ClaimIdentity by resolving the
// server's identity for this agent and looking for a matching local key.
// If found, it returns the identity fields to persist. Otherwise it exits
// with a descriptive error.
func recoverIdentity409(
	ctx context.Context,
	client *aweb.Client,
	keysDir, address string,
) (did, signingKeyPath, custody, lifetime string) {
	resolver := &aweb.ServerResolver{Client: client}
	identity, err := resolver.Resolve(ctx, address)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Identity already set on server, and could not resolve %s to recover: %v\n", address, err)
		fmt.Fprintln(os.Stderr, "Run 'aw reset --remote --confirm' to clear the server identity and re-provision.")
		os.Exit(1)
	}

	serverPub, err := aweb.ExtractPublicKey(identity.DID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Identity already set on server with invalid DID %q: %v\n", identity.DID, err)
		os.Exit(1)
	}

	// Fast path: check expected key location.
	expectedPath := awconfig.SigningKeyPath(keysDir, address)
	priv, loadErr := awconfig.LoadSigningKey(expectedPath)
	if loadErr == nil {
		loadedPub := priv.Public().(ed25519.PublicKey)
		if loadedPub.Equal(serverPub) {
			fmt.Fprintf(os.Stderr, "Recovered identity from existing key at %s\n", expectedPath)
			return identity.DID, expectedPath, identity.Custody, identity.Lifetime
		}
	}

	// Slow path: scan all keys (including rotated/).
	foundPath, err := awconfig.ScanKeysForPublicKey(keysDir, serverPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Identity already set on server; error scanning local keys: %v\n", err)
		os.Exit(1)
	}
	if foundPath != "" {
		if strings.Contains(foundPath, string(os.PathSeparator)+"rotated"+string(os.PathSeparator)) {
			fmt.Fprintf(os.Stderr, "Warning: recovered identity from rotated key at %s — server may be out of sync\n", foundPath)
		} else {
			fmt.Fprintf(os.Stderr, "Recovered identity from existing key at %s\n", foundPath)
		}
		return identity.DID, foundPath, identity.Custody, identity.Lifetime
	}

	fmt.Fprintf(os.Stderr, "Identity already set on server (%s) but no matching signing key found locally.\n", identity.DID)
	fmt.Fprintf(os.Stderr, "To recover, place the signing key at %s, or run 'aw reset --remote --confirm' to clear the server identity and re-provision.\n", expectedPath)
	os.Exit(1)
	return // unreachable
}

// registerClawDIDWithHandle attempts to register the agent's stable_id with ClawDID.
// Returns the stable_id on success, or empty string on failure.
// handle is included in the state_hash and registration request when non-nil.
func registerClawDIDWithHandle(
	ctx context.Context,
	registryURL string,
	pub ed25519.PublicKey, priv ed25519.PrivateKey,
	did, serverURL, address string,
	handle *string,
) string {
	didClaw := aweb.ComputeStableID(pub, "claw")
	stateHash := aweb.ComputeStateHash(didClaw, did, serverURL, address, handle)
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
		Handle:       handle,
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
