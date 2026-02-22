package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

func mustResolve() (*aweb.Client, *awconfig.Selection) {
	cfg, err := awconfig.LoadGlobal()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to read config:", err)
		os.Exit(2)
	}
	wd, _ := os.Getwd()
	sel, err := awconfig.Resolve(cfg, awconfig.ResolveOptions{
		ServerName:        serverFlag,
		AccountName:       accountFlag,
		WorkingDir:        wd,
		AllowEnvOverrides: true,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	baseURL, err := resolveWorkingBaseURL(sel.BaseURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	sel.BaseURL = baseURL

	var c *aweb.Client
	if sel.SigningKey != "" && sel.DID != "" {
		priv, err := awconfig.LoadSigningKey(sel.SigningKey)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to load signing key:", err)
			os.Exit(2)
		}
		c, err = aweb.NewWithIdentity(baseURL, sel.APIKey, priv, sel.DID)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Invalid identity configuration:", err)
			os.Exit(2)
		}
		c.SetAddress(deriveAgentAddress(sel.NamespaceSlug, sel.DefaultProject, sel.AgentAlias))
		c.SetResolver(&aweb.ServerResolver{Client: c})

		// Load TOFU pin store for sender identity verification.
		pinPath := filepath.Join(filepath.Dir(mustDefaultGlobalPath()), "known_agents.yaml")
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
			fmt.Fprintln(os.Stderr, "Invalid base URL:", err)
			os.Exit(2)
		}
	}
	return c, sel
}

func mustClient() *aweb.Client {
	c, _ := mustResolve()
	return c
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

func mustDefaultGlobalPath() string {
	path, err := awconfig.DefaultGlobalConfigPath()
	if err != nil {
		fatal(err)
	}
	return path
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

func deriveAccountName(serverName, projectSlug, alias string) string {
	return "acct-" + sanitizeKeyComponent(serverName) + "__" + sanitizeKeyComponent(projectSlug) + "__" + sanitizeKeyComponent(alias)
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

func fatal(err error) {
	msg := err.Error()
	if hint := checkVerificationRequired(err); hint != "" {
		msg = hint
	}
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
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

func debugLog(format string, args ...any) {
	if debugFlag {
		fmt.Fprintf(os.Stderr, "[debug] "+format+"\n", args...)
	}
}
