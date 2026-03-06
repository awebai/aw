package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/joho/godotenv"
)

func loadDotenvBestEffort() {
	// Best effort: load from current working directory.
	_ = godotenv.Load()
	_ = godotenv.Overload(".env.aweb")
}

// lastClient holds the most recently created client, used to check
// the X-Latest-Client-Version header after command execution.
var lastClient *aweb.Client

func resolveClientSelection() (*aweb.Client, *awconfig.Selection, error) {
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read config: %w", err)
	}
	wd, _ := os.Getwd()
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ServerName:        serverFlag,
		AccountName:       accountFlag,
		ClientName:        "aw",
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

	lastClient = c
	return c, sel, nil
}

func resolveClient() (*aweb.Client, error) {
	c, _, err := resolveClientSelection()
	return c, err
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
		ClientName:        "aw",
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
	lastClient = c
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

func probeAwebBaseURL(ctx context.Context, baseURL string) (bool, error) {
	// Stable across our servers: exists (POST) on /v1/agents/heartbeat.
	// We use GET to avoid side effects; success is any non-404 response.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/v1/agents/heartbeat", nil)
	if err != nil {
		return false, err
	}
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		return false, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode != http.StatusNotFound, nil
}

func resolveWorkingBaseURL(raw string) (string, error) {
	base, err := cleanBaseURL(raw)
	if err != nil {
		return "", err
	}

	candidates := make([]string, 0, 4)
	add := func(v string) {
		v = strings.TrimSuffix(strings.TrimSpace(v), "/")
		if v == "" {
			return
		}
		for _, existing := range candidates {
			if existing == v {
				return
			}
		}
		candidates = append(candidates, v)
	}

	add(base)
	if strings.HasSuffix(base, "/v1") {
		add(strings.TrimSuffix(base, "/v1"))
	}
	if strings.HasSuffix(base, "/api/v1") {
		add(strings.TrimSuffix(base, "/v1"))
	}
	if !strings.HasSuffix(base, "/api") {
		add(base + "/api")
	}

	var lastErr error
	for _, cand := range candidates {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ok, err := probeAwebBaseURL(ctx, cand)
		cancel()
		if err != nil {
			lastErr = err
			continue
		}
		if ok {
			return cand, nil
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("no aweb API detected at %q (tried %v): %w", raw, candidates, lastErr)
	}
	return "", fmt.Errorf("no aweb API detected at %q (tried %v)", raw, candidates)
}

// fireHeartbeat sends a best-effort heartbeat to the aweb server.
// Called as a goroutine on every authenticated command invocation.
func fireHeartbeat() {
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		debugLog("heartbeat: load config: %v", err)
		return
	}
	wd, _ := os.Getwd()
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		WorkingDir:        wd,
		AllowEnvOverrides: true,
	})
	if err != nil {
		debugLog("heartbeat: resolve account: %v", err)
		return
	}
	if sel.APIKey == "" {
		debugLog("heartbeat: no API key configured")
		return
	}
	baseURL, err := resolveWorkingBaseURL(sel.BaseURL)
	if err != nil {
		debugLog("heartbeat: %v", err)
		return
	}
	c, err := aweb.NewWithAPIKey(baseURL, sel.APIKey)
	if err != nil {
		debugLog("heartbeat: create client: %v", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.Heartbeat(ctx); err != nil {
		debugLog("heartbeat: %v", err)
	}
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
	return awconfig.DefaultGlobalConfigPath()
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
	return writeOrUpdateContextWithOptions(serverName, accountName, true)
}

func writeOrUpdateContextWithOptions(serverName, accountName string, setDefault bool) error {
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
		// Multi-server-friendly: keep the existing default unless explicitly asked
		// to override it, while still adding/updating the per-server mapping.
		if strings.TrimSpace(ctx.DefaultAccount) == "" || setDefault {
			ctx.DefaultAccount = accountName
		}
		ctx.ServerAccounts[serverName] = accountName
	}
	if ctx.ClientDefaultAccounts == nil {
		ctx.ClientDefaultAccounts = map[string]string{}
	}
	// `aw` should default to the last identity set by `aw` in this directory.
	ctx.ClientDefaultAccounts["aw"] = accountName

	return awconfig.SaveWorktreeContextTo(ctxPath, ctx)
}

func printJSON(v any) {
	data, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(data))
}

func printOutput(v any, formatter func(v any) string) {
	if jsonFlag {
		printJSON(v)
		return
	}
	fmt.Print(formatter(v))
}

func parseTimeBestEffort(value string) (time.Time, bool) {
	if value == "" {
		return time.Time{}, false
	}
	if ts, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return ts, true
	}
	if ts, err := time.Parse(time.RFC3339, value); err == nil {
		return ts, true
	}
	return time.Time{}, false
}

func formatTimeAgo(timestamp string) string {
	ts, ok := parseTimeBestEffort(timestamp)
	if !ok {
		return timestamp
	}
	d := time.Since(ts)
	if d < 0 {
		d = 0
	}
	secs := int(d.Seconds())
	if secs < 60 {
		return fmt.Sprintf("%ds ago", secs)
	}
	mins := secs / 60
	if mins < 60 {
		return fmt.Sprintf("%dm ago", mins)
	}
	hours := mins / 60
	if hours < 48 {
		return fmt.Sprintf("%dh ago", hours)
	}
	days := hours / 24
	return fmt.Sprintf("%dd ago", days)
}

func formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		mins := seconds / 60
		secs := seconds % 60
		if secs == 0 {
			return fmt.Sprintf("%dm", mins)
		}
		return fmt.Sprintf("%dm%ds", mins, secs)
	}
	hours := seconds / 3600
	mins := (seconds % 3600) / 60
	if mins == 0 {
		return fmt.Sprintf("%dh", hours)
	}
	return fmt.Sprintf("%dh%dm", hours, mins)
}

func ttlRemainingSeconds(expiresAt string, now time.Time) int {
	if expiresAt == "" {
		return 0
	}
	ts, err := time.Parse(time.RFC3339Nano, expiresAt)
	if err != nil {
		ts, err = time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return 0
		}
	}
	secs := int(math.Ceil(ts.Sub(now).Seconds()))
	if secs < 0 {
		return 0
	}
	return secs
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
	hint += ". Run 'aw verify --code CODE' to activate your agent."
	return hint
}

// networkError wraps an error with a user-friendly message for network 404 errors.
// When a network send fails because the target agent doesn't exist, the raw error
// is "aweb: http 404: ..." which looks like a broken endpoint. This rewrites it
// to mention the target address.
func networkError(err error, target string) error {
	code, ok := aweb.HTTPStatusCode(err)
	if ok && code == 404 {
		return fmt.Errorf("agent not found: %s", target)
	}
	return err
}

func debugLog(format string, args ...any) {
	if debugFlag {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
