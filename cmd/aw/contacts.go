package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var contactsAddLabel string

var contactsCmd = &cobra.Command{
	Use:   "contacts",
	Short: "Manage contacts",
}

var contactsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List contacts",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().ListContacts(ctx)
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

var contactsAddCmd = &cobra.Command{
	Use:   "add <address>",
	Short: "Add a contact",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		resp, err := mustClient().CreateContact(ctx, &aweb.ContactCreateRequest{
			ContactAddress: args[0],
			Label:          contactsAddLabel,
		})
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

var contactsRemoveCmd = &cobra.Command{
	Use:   "remove <address>",
	Short: "Remove a contact by address",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		client := mustClient()

		// List contacts to find the ID for the given address.
		list, err := client.ListContacts(ctx)
		if err != nil {
			fatal(err)
		}

		address := args[0]
		var contactID string
		for _, c := range list.Contacts {
			if c.ContactAddress == address {
				contactID = c.ContactID
				break
			}
		}
		if contactID == "" {
			fatal(fmt.Errorf("contact not found: %s", address))
		}

		resp, err := client.DeleteContact(ctx, contactID)
		if err != nil {
			fatal(err)
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	contactsAddCmd.Flags().StringVar(&contactsAddLabel, "label", "", "Label for the contact")
	contactsCmd.AddCommand(contactsListCmd)
	contactsCmd.AddCommand(contactsAddCmd)
	contactsCmd.AddCommand(contactsRemoveCmd)
	rootCmd.AddCommand(contactsCmd)
}
