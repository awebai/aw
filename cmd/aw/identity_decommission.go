package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var identityDecommissionConfirm bool

var identityDecommissionCmd = &cobra.Command{
	Use:   "decommission",
	Short: "Decommission the current ephemeral identity",
	Long:  "Deletes the current ephemeral identity on the server and removes the matching local workspace/account state.",
	RunE:  runIdentityDecommission,
}

func init() {
	identityDecommissionCmd.Flags().BoolVar(&identityDecommissionConfirm, "confirm", false, "Required to decommission the current ephemeral identity")
	identityCmd.AddCommand(identityDecommissionCmd)
}

func runIdentityDecommission(cmd *cobra.Command, args []string) error {
	if !identityDecommissionConfirm {
		return usageError("identity decommission requires --confirm")
	}

	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lifetime, custody := resolveSelectionIdentityState(ctx, client, sel)
	if awid.IdentityClassFromLifetime(lifetime) == awid.IdentityClassPermanent {
		return usageError("the current identity is permanent; use `aw identity replace --successor ...` for continuity, or archive it from the dashboard when that flow is available")
	}
	if awid.IdentityClassFromLifetime(lifetime) != awid.IdentityClassEphemeral {
		return fmt.Errorf("could not confirm that the current identity is ephemeral")
	}

	if err := client.Deregister(ctx); err != nil {
		return err
	}

	configRemoved, contextRemoved, keyRemoved, err := cleanupDecommissionedIdentity(sel)
	if err != nil {
		return err
	}

	fmt.Println("Identity decommissioned.")
	if strings.TrimSpace(sel.AgentAlias) != "" {
		fmt.Printf("Alias:       %s\n", strings.TrimSpace(sel.AgentAlias))
	}
	if custody != "" {
		fmt.Printf("Custody:     %s\n", custody)
	}
	fmt.Printf("Identity:    %s\n", describeIdentityClass(lifetime))
	if configRemoved != "" {
		fmt.Printf("Config:      removed %s\n", configRemoved)
	}
	if contextRemoved != "" {
		fmt.Printf("Workspace:   removed %s\n", contextRemoved)
	}
	if keyRemoved != "" {
		fmt.Printf("Key:         removed %s\n", keyRemoved)
	}
	return nil
}

func resolveSelectionIdentityState(ctx context.Context, client *aweb.Client, sel *awconfig.Selection) (lifetime, custody string) {
	lifetime = strings.TrimSpace(sel.Lifetime)
	custody = strings.TrimSpace(sel.Custody)
	if lifetime != "" && custody != "" {
		return lifetime, custody
	}

	namespaceSlug := strings.TrimSpace(sel.NamespaceSlug)
	if namespaceSlug == "" {
		if project, err := client.GetCurrentProject(ctx); err == nil {
			namespaceSlug = strings.TrimSpace(project.Slug)
		}
	}

	_, _, resolvedCustody, resolvedLifetime := resolveServerIdentityState(ctx, client, namespaceSlug, strings.TrimSpace(sel.AgentAlias), "")
	if strings.TrimSpace(resolvedLifetime) != "" {
		lifetime = strings.TrimSpace(resolvedLifetime)
	}
	if strings.TrimSpace(resolvedCustody) != "" {
		custody = strings.TrimSpace(resolvedCustody)
	}
	return lifetime, custody
}

func cleanupDecommissionedIdentity(sel *awconfig.Selection) (configRemoved, contextRemoved, keyRemoved string, err error) {
	if strings.TrimSpace(sel.SigningKey) != "" {
		if removeErr := removeSigningKeyFiles(strings.TrimSpace(sel.SigningKey)); removeErr != nil {
			return "", "", "", removeErr
		}
		keyRemoved = strings.TrimSpace(sel.SigningKey)
	}

	if strings.TrimSpace(sel.AccountName) != "" {
		cfgPath, cfgErr := defaultGlobalPath()
		if cfgErr != nil {
			return "", "", keyRemoved, cfgErr
		}
		if err := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
			if cfg.Accounts != nil {
				delete(cfg.Accounts, sel.AccountName)
			}
			if strings.TrimSpace(cfg.DefaultAccount) == strings.TrimSpace(sel.AccountName) {
				cfg.DefaultAccount = firstRemainingAccount(cfg)
			}
			if cfg.ClientDefaultAccounts != nil && strings.TrimSpace(cfg.ClientDefaultAccounts["aw"]) == strings.TrimSpace(sel.AccountName) {
				delete(cfg.ClientDefaultAccounts, "aw")
			}
			return nil
		}); err != nil {
			return "", "", keyRemoved, err
		}
		configRemoved = strings.TrimSpace(sel.AccountName)
	}

	contextRemoved, err = removeCurrentContextBinding(strings.TrimSpace(sel.AccountName))
	if err != nil {
		return configRemoved, "", keyRemoved, err
	}

	return configRemoved, contextRemoved, keyRemoved, nil
}

func firstRemainingAccount(cfg *awconfig.GlobalConfig) string {
	for _, name := range sortedAccountNames(cfg) {
		return name
	}
	return ""
}

func removeSigningKeyFiles(signingKeyPath string) error {
	if err := os.Remove(signingKeyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	pubPath := strings.TrimSuffix(signingKeyPath, ".key") + ".pub"
	if err := os.Remove(pubPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func removeCurrentContextBinding(accountName string) (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	ctxPath, err := awconfig.FindWorktreeContextPath(wd)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}

	ctx, err := awconfig.LoadWorktreeContextFrom(ctxPath)
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(accountName) != "" {
		if strings.TrimSpace(ctx.DefaultAccount) == accountName {
			ctx.DefaultAccount = ""
		}
		for serverName, mappedAccount := range ctx.ServerAccounts {
			if strings.TrimSpace(mappedAccount) == accountName {
				delete(ctx.ServerAccounts, serverName)
			}
		}
		for clientName, mappedAccount := range ctx.ClientDefaultAccounts {
			if strings.TrimSpace(mappedAccount) == accountName {
				delete(ctx.ClientDefaultAccounts, clientName)
			}
		}
	}

	if strings.TrimSpace(ctx.DefaultAccount) == "" {
		for _, mappedAccount := range ctx.ServerAccounts {
			ctx.DefaultAccount = mappedAccount
			break
		}
	}
	if strings.TrimSpace(ctx.DefaultAccount) == "" {
		for _, mappedAccount := range ctx.ClientDefaultAccounts {
			ctx.DefaultAccount = mappedAccount
			break
		}
	}

	if strings.TrimSpace(ctx.DefaultAccount) == "" && len(ctx.ServerAccounts) == 0 && len(ctx.ClientDefaultAccounts) == 0 && strings.TrimSpace(ctx.HumanAccount) == "" {
		if err := os.Remove(ctxPath); err != nil && !os.IsNotExist(err) {
			return "", err
		}
		awDir := filepath.Dir(ctxPath)
		entries, readErr := os.ReadDir(awDir)
		if readErr == nil && len(entries) == 0 {
			_ = os.Remove(awDir)
		}
		return ctxPath, nil
	}

	if err := awconfig.SaveWorktreeContextTo(ctxPath, ctx); err != nil {
		return "", err
	}
	return ctxPath, nil
}
