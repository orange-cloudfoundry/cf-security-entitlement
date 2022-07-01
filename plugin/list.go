package main

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type ListCommand struct {
	Api string `short:"a" long:"api" description:"api to cf security"`
}

var listCommand ListCommand

func (c *ListCommand) Execute(_ []string) error {
	client := genClient(c.Api)
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	messages.Printf("Getting security groups as %s...\n", messages.C.Cyan(username))
	secGroups, err := client.ListSecGroups()
	if err != nil {
		return err
	}
	messages.Println(messages.C.Green("OK\n"))

	if len(secGroups.Resources) == 0 {
		return nil
	}
	data := make([][]string, 0)
	for iSec, secGroup := range secGroups.Resources {
		subData := make([]string, 0)
		subData = append(subData, fmt.Sprintf("#%d", iSec))
		subData = append(subData, secGroup.Name)
		if len(secGroup.Relationships.Running_spaces.Data) == 0 || len(secGroup.Relationships.Staging_spaces.Data) == 0 {
			subData = append(subData, "", "", "")
			data = append(data, subData)
			continue
		}
		// à revoir
		for iSpace, space := range secGroup.Relationships.Running_spaces.Data {
			if iSpace > 0 {
				subData = make([]string, 0)
				subData = append(subData, "", "")
			}
			subData = append(subData, space.OrgName, space.SpaceName)
			data = append(data, append(subData, "running"))
			if iSpace == 0 {
				subData[0] = ""
				subData[1] = ""
			}
			data = append(data, append(subData, "staging"))
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"#", "name", "organization", "space", "lifecycle"})
	table.AppendBulk(data)
	table.SetRowSeparator("")
	table.SetAutoFormatHeaders(false)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetBorder(false)
	table.SetHeaderLine(false)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetRowLine(false)
	table.Render()
	return nil
}

func init() {
	desc := `List all security groups available for an org manager`
	_, err := parser.AddCommand(
		"manager-security-groups",
		desc,
		desc,
		&listCommand)
	if err != nil {
		panic(err)
	}
}
