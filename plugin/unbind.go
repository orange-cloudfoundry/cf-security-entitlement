package main

import (
	"fmt"
	"net/http"

	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type UnbindCommand struct {
	Api         string      `short:"a" long:"api" description:"api to cf security"`
	BindOptions BindOptions `required:"2" positional-args:"true"`
}

var unbindCommand UnbindCommand

func (c *UnbindCommand) Execute(_ []string) error {
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	spaceShow := c.BindOptions.Space
	if spaceShow != "" {
		spaceShow = "/" + fmt.Sprint(messages.C.Cyan(spaceShow))
	}
	messages.Printf(
		"Unbinding security groups %s to %s%s as %s...\n",
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
		err := client.BindUnbindSecurityGroup(secGroup.GUID, space.Guid, http.MethodDelete, client.GetEndpoint())
		if err != nil {
			return err
		}
	}
	messages.Println(messages.C.Green("OK\n"))
	messages.Println("TIP: If Dynamic ASG's are enabled, changes will automatically apply for running and staging applications. Otherwise, changes will require an app restart (for running) or restage (for staging) to apply to existing applications.")
	return nil
}

func init() {
	desc := `Unbind a security group to a particular space, or all existing spaces of an org by an org manager`
	_, err := parser.AddCommand(
		"unbind-manager-security-group",
		desc,
		desc,
		&unbindCommand)
	if err != nil {
		panic(err)
	}
}
