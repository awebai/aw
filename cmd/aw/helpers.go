package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/joho/godotenv"
)

func loadDotenvBestEffort() {
	// Best effort: load from current working directory.
	_ = godotenv.Load()
	_ = godotenv.Overload(".env.aweb")
}

func resolveClientSelection() (*aweb.Client, *awconfig.Selection, error) {
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}
	wd, _ := os.Getwd()
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ServerName:        serverFlag,
		AccountName:       accountFlag,
		WorkingDir:        wd,
		AllowEnvOverrides: true,
	})
	if err != nil {
		return nil, nil, err
	}

	baseURL, err := resolveWorkingBaseURL(sel.BaseURL)
	if err != nil {
		return nil, nil, err
	}
	sel.BaseURL = baseURL

	var c *aweb.Client
	if sel.SigningKey != "" && sel.DID != "" {
		priv, err := awconfig.LoadSigningKey(sel.SigningKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to load signing key: %w", err)
		}
		c, err = aweb.NewWithIdentity(baseURL, sel.APIKey, priv, sel.DID)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid identity configuration: %w", err)
		}
		c.SetAddress(deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias))
		if sel.StableID != "" {
			c.SetStableID(sel.StableID)
		}
		c.SetResolver(&aweb.ServerResolver{Client: c})

		// Load TOFU pin store for sender identity verification.
		cfgPath, err := defaultGlobalPath()
		if err != nil {
			return nil, nil, err
		}
		pinPath := filepath.Join(filepath.Dir(cfgPath), "known_agents.yaml")
		ps, err := aweb.LoadPinStore(pinPath)
		if err != nil {
			debugLog("load pin store: %v", err)
			ps = aweb.NewPinStore()
		}
		c.SetPinStore(ps, pinPath)
	} else {
		var err error
		c, err = aweb.NewWithAPIKey(baseURL, sel.APIKey)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid base URL: %w", err)
		}
	}

	// Enable ClawDID split-trust verification when a registry URL is configured.
	if sel.ClawDIDRegistryURL != "" {
		c.SetClawDIDClient(&aweb.ClawDIDClient{RegistryURL: sel.ClawDIDRegistryURL})
	}

	return c, sel, nil
}

func resolveClient() (*aweb.Client, error) {
	c, _, err := resolveClientSelection()
	if err != nil {
		return nil, err
	}
	return c, nil
}

// resolveAPIKeyOnly resolves config and creates a client using only
// the API key (no signing key). Used by commands like reset that need
// to work even when the local signing key is missing or invalid.
func resolveAPIKeyOnly() (*aweb.Client, *awconfig.Selection, error) {
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}
	wd, _ := os.Getwd()
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ServerName:        serverFlag,
		AccountName:       accountFlag,
		WorkingDir:        wd,
		AllowEnvOverrides: true,
	})
	if err != nil {
		return nil, nil, err
	}

	baseURL, err := resolveWorkingBaseURL(sel.BaseURL)
	if err != nil {
		return nil, nil, err
	}
	sel.BaseURL = baseURL

	c, err := aweb.NewWithAPIKey(baseURL, sel.APIKey)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid base URL: %w", err)
	}
	return c, sel, nil
}

// canonicalOrigin extracts scheme+host from a URL, stripping any path.
// For example, "https://app.claweb.ai/api" → "https://app.claweb.ai".
func canonicalOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	return u.Scheme + "://" + u.Host
}

// resolveClawDIDRegistryURL returns the ClawDID registry URL from env, config, or default.
func resolveClawDIDRegistryURL(cfgPath string) string {
	if v := strings.TrimSpace(os.Getenv("CLAWDID_REGISTRY_URL")); v != "" {
		return v
	}
	cfg, err := awconfig.LoadGlobalFrom(cfgPath)
	if err == nil && strings.TrimSpace(cfg.ClawDIDRegistryURL) != "" {
		return strings.TrimSpace(cfg.ClawDIDRegistryURL)
	}
	return awconfig.DefaultClawDIDRegistryURL
}

func cleanBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty base url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid base url %q", raw)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func resolveWorkingBaseURL(raw string) (string, error) {
	base, err := cleanBaseURL(raw)
	if err != nil {
		return "", err
	}
	return base, nil
}

func resolveBaseURLForInit(urlVal, serverVal string) (baseURL string, serverName string, global *awconfig.GlobalConfig, err error) {
	global, err = awconfig.LoadGlobal()
	if err != nil {
		return "", "", nil, err
	}

	wd, _ := os.Getwd()
	ctx, _, _ := awconfig.LoadWorktreeContextFromDir(wd)

	baseURL = strings.TrimSpace(urlVal)
	serverName = strings.TrimSpace(serverVal)

	if baseURL == "" {
		baseURL = strings.TrimSpace(os.Getenv("AWEB_URL"))
	}
	// If the user didn't specify a server/url, prefer the current worktree context
	// (keeps "init/rotate" operations scoped to the same server as normal commands).
	if baseURL == "" && serverName == "" && ctx != nil {
		if v := strings.TrimSpace(ctx.DefaultAccount); v != "" {
			if acct, ok := global.Accounts[v]; ok {
				serverName = strings.TrimSpace(acct.Server)
			}
		}
		if serverName == "" && len(ctx.ServerAccounts) == 1 {
			for k := range ctx.ServerAccounts {
				serverName = strings.TrimSpace(k)
				break
			}
		}
	}
	if baseURL == "" && serverName != "" {
		if srv, ok := global.Servers[serverName]; ok && strings.TrimSpace(srv.URL) != "" {
			baseURL = strings.TrimSpace(srv.URL)
		} else {
			baseURL, err = awconfig.DeriveBaseURLFromServerName(serverName)
			if err != nil {
				return "", "", nil, err
			}
		}
	}
	if baseURL == "" && strings.TrimSpace(global.DefaultAccount) != "" {
		if acct, ok := global.Accounts[strings.TrimSpace(global.DefaultAccount)]; ok {
			serverName = strings.TrimSpace(acct.Server)
			if srv, ok := global.Servers[serverName]; ok && strings.TrimSpace(srv.URL) != "" {
				baseURL = strings.TrimSpace(srv.URL)
			} else if serverName != "" {
				baseURL, err = awconfig.DeriveBaseURLFromServerName(serverName)
				if err != nil {
					return "", "", nil, err
				}
			}
		}
	}
	if baseURL == "" {
		return "", "", nil, fmt.Errorf("no server selected (pass --server-url, set AWEB_URL, or configure a default account in your aw config)")
	}
	if serverName == "" {
		derived, derr := awconfig.DeriveServerNameFromURL(baseURL)
		if derr == nil {
			serverName = derived
		}
	}
	if err := awconfig.ValidateBaseURL(baseURL); err != nil {
		return "", "", nil, err
	}
	baseURL, err = resolveWorkingBaseURL(baseURL)
	if err != nil {
		return "", "", nil, err
	}
	return baseURL, serverName, global, nil
}

func isTTY() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func sanitizeSlug(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "demo"
	}
	return out
}

func promptString(label, defaultValue string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Fprintf(os.Stderr, "%s [%s]: ", label, defaultValue)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return defaultValue, nil
	}
	return line, nil
}

func defaultGlobalPath() (string, error) {
	path, err := awconfig.DefaultGlobalConfigPath()
	if err != nil {
		return "", err
	}
	return path, nil
}

func sanitizeKeyComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "x"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.'
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "x"
	}
	return out
}

func deriveAccountName(serverName, namespaceSlug, alias string) string {
	return "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(namespaceSlug) + "__" + sanitizeKeyComponent(alias)
}

// deriveAgentAddress builds the agent address (namespace/alias) from
// registration response fields. Prefers namespace_slug over project_slug.
func deriveAgentAddress(namespaceSlug, projectSlug, alias string) string {
	if namespaceSlug != "" {
		return namespaceSlug + "/" + alias
	}
	if projectSlug != "" {
		return projectSlug + "/" + alias
	}
	return alias
}

func writeOrUpdateContext(serverName, accountName string) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}

	ctxPath, err := awconfig.FindWorktreeContextPath(wd)
	if err != nil {
		ctxPath = filepath.Join(wd, awconfig.DefaultWorktreeContextRelativePath())
	}

	ctx := &awconfig.WorktreeContext{
		DefaultAccount: accountName,
		ServerAccounts: map[string]string{serverName: accountName},
	}
	if existing, err := awconfig.LoadWorktreeContextFrom(ctxPath); err == nil {
		ctx = existing
		if ctx.ServerAccounts == nil {
			ctx.ServerAccounts = map[string]string{}
		}
		ctx.DefaultAccount = accountName
		ctx.ServerAccounts[serverName] = accountName
	}

	return awconfig.SaveWorktreeContextTo(ctxPath, ctx)
}

func printJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

// checkVerificationRequired detects EMAIL_VERIFICATION_REQUIRED 403 errors
// and returns a user-friendly message. Returns "" for non-matching errors.
func checkVerificationRequired(err error) string {
	statusCode, ok := aweb.HTTPStatusCode(err)
	if !ok || statusCode != 403 {
		return ""
	}
	body, ok := aweb.HTTPErrorBody(err)
	if !ok {
		return ""
	}
	var envelope struct {
		Error struct {
			Code    string `json:"code"`
			Details struct {
				MaskedEmail string `json:"masked_email"`
			} `json:"details"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil || envelope.Error.Code != "EMAIL_VERIFICATION_REQUIRED" {
		return ""
	}
	hint := "email verification required"
	if envelope.Error.Details.MaskedEmail != "" {
		hint += " (" + envelope.Error.Details.MaskedEmail + ")"
	}
	hint += "; run 'aw verify --code CODE' to activate your agent"
	return hint
}

func debugLog(format string, args ...any) {
	if debugFlag {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
