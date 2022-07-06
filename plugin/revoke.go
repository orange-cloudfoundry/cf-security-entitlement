package main

import (
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type RevokeCommand struct {
	Api                string             `short:"a" long:"api" description:"api to cf security"`
	EntitlementOptions EntitlementOptions `required:"2" positional-args:"true"`
}

var revokeCommand RevokeCommand

func (c *RevokeCommand) Execute(_ []string) error {
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	messages.Printf(
		"Revoking security groups %s to %s as %s...\n",
		messages.C.Cyan(c.EntitlementOptions.SecurityGroup),
		messages.C.Cyan(c.EntitlementOptions.Org),
		messages.C.Cyan(username),
	)
	orgId, err := getOrgID(c.EntitlementOptions.Org)
	if err != nil {
		return err
	}
	client := genClient(c.Api)
	secGroup, err := client.GetSecGroupByName(c.EntitlementOptions.SecurityGroup)
	if err != nil {
		return err
	}
	err = client.RevokeSecurityGroup(secGroup.GUID, orgId)
	if err != nil {
		return err
	}
	messages.Println(messages.C.Green("OK\n"))
	messages.Println(messages.C.Yellow("Important"), ": For avoiding breaking app you need to unbind-security-group in the org yourself.")
	return nil
}

func init() {
	desc := `Revoke an organization to a security group`
	_, err := parser.AddCommand(
		"disable-security-group",
		desc,
		desc,
		&revokeCommand)
	if err != nil {
		panic(err)
	}
}
