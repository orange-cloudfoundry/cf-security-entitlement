package main

import (
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type EntitlementOptions struct {
	SecurityGroup string `positional-arg-name:"SECURITY-GROUP"`
	Org           string `positional-arg-name:"ORG"`
}

type EnableCommand struct {
	Api                string             `short:"a" long:"api" description:"api to cf security"`
	EntitlementOptions EntitlementOptions `required:"2" positional-args:"true"`
}

var enableCommand EnableCommand

func (c *EnableCommand) Execute(_ []string) error {
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	messages.Printf(
		"Entitling security groups %s to %s as %s...\n",
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

	err = client.EntitleSecurityGroup(secGroup.Resources[0].GUID, orgId)
	if err != nil {
		return err
	}
	messages.Println(messages.C.Green("OK\n"))
	return nil
}

func init() {
	desc := `Entitle an organization to a security group`
	_, err := parser.AddCommand(
		"enable-security-group",
		desc,
		desc,
		&enableCommand)
	if err != nil {
		panic(err)
	}
}
