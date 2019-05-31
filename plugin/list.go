package main

import (
	"fmt"
	"github.com/olekukonko/tablewriter"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
	"os"
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

	if len(secGroups) == 0 {
		fmt.Println("Empty.")
		return nil
	}
	data := make([][]string, 0)
	for iSec, secGroup := range secGroups {
		subData := make([]string, 0)
		subData = append(subData, fmt.Sprintf("#%d", iSec))
		subData = append(subData, secGroup.Name)
		if len(secGroup.SpacesData) == 0 {
			subData = append(subData, "", "", "")
			data = append(data, subData)
			continue
		}
		for iSpace, space := range secGroup.SpacesData {
			if iSpace > 0 {
				subData = make([]string, 0)
				subData = append(subData, "", "")
			}
			subData = append(subData, space.Entity.OrgData.Entity.Name, space.Entity.Name)
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
