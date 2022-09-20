package main

import (
	"encoding/json"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type GetOptions struct {
	SecurityGroup string `positional-arg-name:"SECURITY-GROUP"`
}

type GetCommand struct {
	Api        string     `short:"a" long:"api" description:"api to cf security"`
	GetOptions GetOptions `required:"2" positional-args:"true"`
}

var getCommand GetCommand

func (c *GetCommand) Execute(_ []string) error {
	client := genClient(c.Api)
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	messages.Printf("Getting security group %s as %s...\n",
		messages.C.Cyan(c.GetOptions.SecurityGroup),
		messages.C.Cyan(username),
	)
	secGroup, err := client.GetSecGroupByName(c.GetOptions.SecurityGroup)
	errRelShips := client.AddSecGroupRelationShips(&secGroup)
	if err != nil || errRelShips != nil {
		return err
	}
	messages.Println(
		messages.C.Cyan("Name\t"),
		secGroup.Name,
	)
	messages.Println(messages.C.Cyan("Rules"))
	b, _ := json.MarshalIndent(secGroup.Rules, "\t", "\t")
	messages.Println("\t" + string(b) + "\n")

	data := make([][]string, 0)
	for i, space := range secGroup.Relationships.RunningSpaces.Data {
		data = append(data, []string{
			messages.C.Sprintf(messages.C.Cyan("#%d"), i),
			space.OrgName,
			space.SpaceName,
		})
	}

	for i, space := range secGroup.Relationships.StagingSpaces.Data {
		data = append(data, []string{
			messages.C.Sprintf(messages.C.Cyan("#%d"), i),
			space.OrgName,
			space.SpaceName,
		})
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"#", "organization", "space"})
	table.AppendBulk(data)
	table.SetRowSeparator("")
	table.SetAutoFormatHeaders(false)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetBorder(false)
	table.SetHeaderLine(false)
	table.SetRowLine(false)
	table.Render()
	return nil
}

func init() {
	desc := `Show a single security group available for an org manager`
	_, err := parser.AddCommand(
		"manager-security-group",
		desc,
		desc,
		&getCommand)
	if err != nil {
		panic(err)
	}
}
