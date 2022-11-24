package main

import (
	"fmt"

	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type BindOptions struct {
	SecurityGroup string `positional-arg-name:"SECURITY-GROUP"`
	Org           string `positional-arg-name:"ORG"`
	Space         string `positional-arg-name:"SPACE"`
}

type BindCommand struct {
	Api         string      `short:"a" long:"api" description:"api to cf security"`
	BindOptions BindOptions `required:"2" positional-args:"true"`
}

var bindCommand BindCommand

func (c *BindCommand) Execute(_ []string) error {
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	spaceShow := c.BindOptions.Space
	if spaceShow != "" {
		spaceShow = "/" + fmt.Sprint(messages.C.Cyan(spaceShow))
	}
	messages.Printf(
		"Binding security groups %s to %s%s as %s...\n",
		messages.C.Cyan(c.BindOptions.SecurityGroup),
		messages.C.Cyan(c.BindOptions.Org),
		spaceShow,
		messages.C.Cyan(username),
	)
	client := genClient(c.Api)
	secGroup, err := client.GetSecGroupByName(c.BindOptions.SecurityGroup)
	if err != nil {
		return err
	}
	orgId, err := getOrgID(c.BindOptions.Org)
	if err != nil {
		return err
	}

	spaces, err := getOrgSpaces(orgId)
	if err != nil {
		return err
	}
	for _, space := range spaces {
		if c.BindOptions.Space != "" && c.BindOptions.Space != space.Name {
			continue
		}
		err := client.BindSecurityGroup(secGroup.GUID, space.Guid, client.GetEndpoint())
		if err != nil {
			return err
		}
		messages.Println(messages.C.Green("OK\n"))
		messages.Println("TIP: If Dynamic ASG's are enabled, changes will automatically apply for running and staging applications. Otherwise, changes will require an app restart (for running) or restage (for staging) to apply to existing applications.")
		return nil
	}
	return fmt.Errorf("Space %s not found in org %s", c.BindOptions.Space, c.BindOptions.Org)

}

func init() {
	desc := `Bind a security group to a particular space, or all existing spaces of an org by an org manager`
	_, err := parser.AddCommand(
		"bind-manager-security-group",
		desc,
		desc,
		&bindCommand)
	if err != nil {
		panic(err)
	}
}
