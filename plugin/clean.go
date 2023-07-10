package main

import (
	"encoding/json"
	"github.com/olekukonko/tablewriter"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
	"os"
)

type CleanEntitlementCommand struct {
	Api    string `short:"a" long:"api" description:"api to cf security"`
	InJson bool   `long:"json" description:"see in json"`
}

var cleanEntitlementCommand CleanEntitlementCommand

func (c *CleanEntitlementCommand) Execute(_ []string) error {
	cfclient := genClient(c.Api)
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	if !c.InJson {
		messages.Printf("Cleaning entitlements security groups as %s...\n", messages.C.Cyan(username))
	}
	cDeleted, err := cfclient.CleanSecGroupEntitlements()
	if err != nil {
		return err
	}
	if !c.InJson {
		messages.Println(messages.C.Green("OK\n"))
	}

	if c.InJson {
		b, _ := json.MarshalIndent(cDeleted, "", "\t")
		messages.Println(string(b))
		return nil
	}
	if len(cDeleted) == 0 {
		return nil
	}
	data := make([][]string, 0)
	for _, entitlement := range cDeleted {
		subData := []string{
			entitlement.SecurityGroupGUID,
			entitlement.OrganizationGUID,
		}
		data = append(data, subData)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"asg_guid", "org_guid"})
	table.AppendBulk(data)
	table.SetRowSeparator("")
	table.SetAutoFormatHeaders(false)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetBorder(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetHeaderLine(false)
	table.SetRowLine(false)
	table.Render()
	return nil
}

func init() {
	desc := `Clean unconsistent security groups entitlements`
	_, err := parser.AddCommand(
		"clean-security-group-entitlements",
		desc,
		desc,
		&cleanEntitlementCommand)
	if err != nil {
		panic(err)
	}
}
