package main

import (
	"fmt"
	"os"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	cli "github.com/orange-cloudfoundry/cf-security-entitlement/v2/client"

	"github.com/olekukonko/tablewriter"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/plugin/messages"
)

type ListCommand struct {
	Api    string `short:"a" long:"api" description:"api to cf security"`
	Silent bool   `short:"s" long:"silent" description:"show only security group names"`
}

var listCommand ListCommand

func (c *ListCommand) Execute(_ []string) error {
	client := genClient(c.Api)
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	messages.Printf("Getting security groups as %s...\n", messages.C.Cyan(username))
	if c.Silent {
		messages.Println(messages.C.Cyan("(Silent mode)"))
	}
	secGroups, err := client.GetSecGroups([]ccv3.Query{}, 0)
	if err != nil {
		return err
	}
	if !c.Silent {
		spaces, err := client.GetSpacesWithOrg([]ccv3.Query{{Key: ccv3.Include, Values: []string{"organization"}}}, 0)
		if err != nil {
			return err
		}
		for i := range secGroups.Resources {
			_ = client.AddSecGroupRelationShips(&secGroups.Resources[i], spaces)
		}
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

		// Merge des infos par security group
		spaceInfos := make(map[string]cli.Data)
		for _, space := range secGroup.Relationships.Running_Spaces.Data {
			if space.OrgName != "" && space.SpaceName != "" {
				space.Running = true
				spaceInfos[space.GUID] = space
			}
		}
		for _, space := range secGroup.Relationships.Staging_Spaces.Data {
			if space.OrgName != "" && space.SpaceName != "" {
				if val, ok := spaceInfos[space.GUID]; ok {
					val.Staging = true
					spaceInfos[space.GUID] = val
				} else {
					space.Staging = true
					spaceInfos[space.GUID] = space
				}
			}
		}

		if len(spaceInfos) == 0 {
			subData = append(subData, "", "", "")
			data = append(data, subData)
			continue
		}

		nbLines := 0
		for _, space := range spaceInfos {
			// a new line is created
			if nbLines > 0 {
				subData = make([]string, 0)
				subData = append(subData, "", "")
			}
			if space.Running {
				subData = append(subData, space.OrgName, space.SpaceName)
				data = append(data, append(subData, "running"))
				subData = make([]string, 0)
				subData = append(subData, "", "")
			}
			if space.Staging {
				subData = append(subData, space.OrgName, space.SpaceName)
				data = append(data, append(subData, "staging"))
			}
			nbLines++
		}
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.Header("#", "name", "organization", "space", "lifecycle")
	table.Bulk(data)
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
