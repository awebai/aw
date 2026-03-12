package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	awrun "github.com/awebai/aw/run"
	"github.com/spf13/cobra"
)

func TestRunInitUsesRunConfigWorkflow(t *testing.T) {
	initRunCommandVars()
	var loadedDir string
	var initCalled bool

	oldLoad := runLoadUserConfig
	oldInit := runInitUserConfig
	oldResolveClient := runResolveClientForDir
	oldGetwd := runGetwd
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runInitUserConfig = oldInit
		runResolveClientForDir = oldResolveClient
		runGetwd = oldGetwd
		initRunCommandVars()
	})

	runGetwd = func() (string, error) { return "/tmp/work", nil }
	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) {
		loadedDir = dir
		return awrun.UserConfig{}, nil
	}
	runInitUserConfig = func(in io.Reader, out io.Writer, existing awrun.UserConfig) error {
		initCalled = true
		return nil
	}
	runResolveClientForDir = func(string) (*aweb.Client, *awconfig.Selection, error) {
		t.Fatal("client resolution should not run for --init")
		return nil, nil, nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	runInitConfig = true
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, nil); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if loadedDir != "/tmp/work" {
		t.Fatalf("expected run config load for /tmp/work, got %q", loadedDir)
	}
	if !initCalled {
		t.Fatal("expected run init workflow to execute")
	}
}

func TestRunBuildsLoopOptionsFromConfigAndFlags(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	oldNewProvider := runNewProvider
	oldResolveClient := runResolveClientForDir
	oldNewLoop := runNewLoop
	oldExecuteLoop := runExecuteLoop
	oldNewWake := runNewWakeStream
	oldNewScreen := runNewScreenController
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		runNewProvider = oldNewProvider
		runResolveClientForDir = oldResolveClient
		runNewLoop = oldNewLoop
		runExecuteLoop = oldExecuteLoop
		runNewWakeStream = oldNewWake
		runNewScreenController = oldNewScreen
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) {
		if !strings.HasSuffix(dir, "testdata") {
			t.Fatalf("expected absolute testdata dir, got %q", dir)
		}
		return awrun.UserConfig{}, nil
	}
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		if overrides.BasePrompt == nil || *overrides.BasePrompt != "flag base" {
			t.Fatalf("expected base-prompt override, got %#v", overrides.BasePrompt)
		}
		if overrides.WaitSeconds == nil || *overrides.WaitSeconds != 7 {
			t.Fatalf("expected wait override, got %#v", overrides.WaitSeconds)
		}
		return awrun.Settings{
			BasePrompt:       "resolved base",
			WaitSeconds:      9,
			IdleWaitSeconds:  12,
			CompactThreshold: 61,
			Services:         []awrun.ServiceConfig{{Name: "api", Command: "make api", Description: "API"}},
		}, nil
	}
	runNewProvider = func(name string) (awrun.Provider, error) {
		if name != "claude" {
			t.Fatalf("provider=%q", name)
		}
		return awrun.ClaudeProvider{}, nil
	}
	runResolveClientForDir = func(dir string) (*aweb.Client, *awconfig.Selection, error) {
		if !strings.HasSuffix(dir, "testdata") {
			t.Fatalf("expected selection dir to match working dir, got %q", dir)
		}
		return &aweb.Client{}, &awconfig.Selection{NamespaceSlug: "team", AgentAlias: "rose"}, nil
	}
	runNewWakeStream = func(client *aweb.Client) awrun.WakeStream {
		if client == nil {
			t.Fatal("expected client for wake stream")
		}
		return nil
	}
	runNewScreenController = func(in io.Reader, out io.Writer) *awrun.ScreenController { return nil }

	var capturedLoop *awrun.Loop
	runNewLoop = func(provider awrun.Provider, out io.Writer) *awrun.Loop {
		capturedLoop = awrun.NewLoop(provider, out)
		return capturedLoop
	}

	var capturedOpts awrun.LoopOptions
	runExecuteLoop = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error {
		capturedOpts = opts
		return nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	runWorkingDir = "testdata"
	runContinueMode = true
	runMaxRuns = 3
	runAllowedTools = "Read,Write"
	runModel = "sonnet"
	runProviderName = "claude"
	runAutofeedWork = true
	runCompactPct = 61
	runBasePrompt = "flag base"
	runWaitSeconds = 7
	cmd.Command.Flags().Set("base-prompt", "flag base")
	cmd.Command.Flags().Set("wait", "7")
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	if err := runRun(&cmd.Command, []string{"finish", "the", "migration"}); err != nil {
		t.Fatalf("runRun returned error: %v", err)
	}
	if capturedLoop == nil {
		t.Fatal("expected loop to be constructed")
	}
	if capturedLoop.StatusIdentity != "claude@team:rose" {
		t.Fatalf("status identity=%q", capturedLoop.StatusIdentity)
	}
	if capturedOpts.InitialPrompt != "finish the migration" {
		t.Fatalf("initial prompt=%q", capturedOpts.InitialPrompt)
	}
	if capturedOpts.Prompt != "resolved base" {
		t.Fatalf("prompt=%q", capturedOpts.Prompt)
	}
	if capturedOpts.WaitSeconds != 9 || capturedOpts.IdleWaitSeconds != 12 {
		t.Fatalf("wait settings=%+v", capturedOpts)
	}
	if !capturedOpts.ContinueMode || !capturedOpts.Autofeed {
		t.Fatalf("expected continue and autofeed flags in opts: %+v", capturedOpts)
	}
	if capturedOpts.MaxRuns != 3 || capturedOpts.AllowedTools != "Read,Write" || capturedOpts.Model != "sonnet" {
		t.Fatalf("unexpected opts: %+v", capturedOpts)
	}
	if len(capturedOpts.Services) != 1 || capturedOpts.Services[0].Name != "api" {
		t.Fatalf("expected services in opts, got %+v", capturedOpts.Services)
	}
}

func TestRunRequiresPromptWithoutConfiguredBasePrompt(t *testing.T) {
	initRunCommandVars()

	oldLoad := runLoadUserConfig
	oldResolveSettings := runResolveSettings
	t.Cleanup(func() {
		runLoadUserConfig = oldLoad
		runResolveSettings = oldResolveSettings
		initRunCommandVars()
	})

	runLoadUserConfig = func(dir string) (awrun.UserConfig, error) { return awrun.UserConfig{}, nil }
	runResolveSettings = func(cfg awrun.UserConfig, overrides awrun.SettingOverrides) (awrun.Settings, error) {
		return awrun.Settings{}, nil
	}

	cmd := &cobraCommandClone{Command: *runCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	var stdout, stderr bytes.Buffer
	setRunCommandIO(&cmd.Command, strings.NewReader(""), &stdout, &stderr)

	err := runRun(&cmd.Command, nil)
	if err == nil {
		t.Fatal("expected error")
	}
	var cliErr *cliError
	if !errors.As(err, &cliErr) {
		t.Fatalf("expected cliError, got %T", err)
	}
	if !strings.Contains(err.Error(), "missing prompt") {
		t.Fatalf("unexpected error: %v", err)
	}
}

type cobraCommandClone struct {
	Command cobra.Command
}

func (c *cobraCommandClone) ResetFlagsForTest() {
	c.Command.ResetFlags()
	c.Command.Flags().StringVar(&runBasePrompt, "base-prompt", "", "")
	c.Command.Flags().StringVar(&runWorkPrompt, "work-prompt-suffix", "", "")
	c.Command.Flags().StringVar(&runCommsPrompt, "comms-prompt-suffix", "", "")
	c.Command.Flags().IntVar(&runWaitSeconds, "wait", awrun.DefaultWaitSeconds, "")
	c.Command.Flags().IntVar(&runIdleWait, "idle-wait", awrun.DefaultIdleWaitSeconds, "")
	c.Command.Flags().IntVar(&runCompactPct, "compact-threshold-pct", awrun.DefaultCompactThreshold, "")
	c.Command.Flags().BoolVar(&runContinueMode, "continue", false, "")
	c.Command.Flags().BoolVar(&runContinueMode, "session", false, "")
	c.Command.Flags().IntVar(&runMaxRuns, "max-runs", 0, "")
	c.Command.Flags().StringVar(&runWorkingDir, "dir", "", "")
	c.Command.Flags().StringVar(&runAllowedTools, "allowed-tools", "", "")
	c.Command.Flags().StringVar(&runModel, "model", "", "")
	c.Command.Flags().StringVar(&runProviderName, "provider", "claude", "")
	c.Command.Flags().BoolVar(&runAutofeedWork, "autofeed-work", false, "")
	c.Command.Flags().BoolVar(&runInitConfig, "init", false, "")
}
