package main

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/olekukonko/tablewriter"
	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type EntitleSecGroup struct {
	Name string
	Orgs []string
}

type ListEntitlementCommand struct {
	Api    string `short:"a" long:"api" description:"api to cf security"`
	InJson bool   `long:"json" description:"see in json"`
}

func entitlementsExtract(cfclient *client.Client, entitlements []model.EntitlementSecGroup) ([]EntitleSecGroup, error) {
	currentSecGroup := ""
	entitleSecGroups := make([]EntitleSecGroup, 0)
	orgs := make([]string, 0)
	bufOrg := make(map[string]string)
	var entitleSecGroup EntitleSecGroup
	for _, entitlement := range entitlements {
		if currentSecGroup != entitlement.SecurityGroupGUID && currentSecGroup != "" {
			entitleSecGroup.Orgs = orgs
			entitleSecGroups = append(entitleSecGroups, entitleSecGroup)
		}
		if currentSecGroup != entitlement.SecurityGroupGUID {
			secGroup, err := cfclient.GetSecGroupByGuid(entitlement.SecurityGroupGUID)
			if err != nil {
				switch err.(type) {
				case client.NotFoundError:
					continue
				default:
					return entitleSecGroups, err
				}
			}
			entitleSecGroup = EntitleSecGroup{
				Name: secGroup.Name,
			}
			currentSecGroup = entitlement.SecurityGroupGUID
			orgs = make([]string, 0)
		}
		if org, ok := bufOrg[entitlement.OrganizationGUID]; ok {
			orgs = append(orgs, org)
			continue
		}
		orgName, err := getOrgName(entitlement.OrganizationGUID)
		if err != nil {
			switch err.(type) {
			case client.NotFoundError:
				continue
			default:
				return entitleSecGroups, err
			}
		}
		bufOrg[entitlement.OrganizationGUID] = orgName
		orgs = append(orgs, orgName)
	}
	entitleSecGroup.Orgs = orgs
	entitleSecGroups = append(entitleSecGroups, entitleSecGroup)
	return entitleSecGroups, nil
}

var listEntitlementCommand ListEntitlementCommand

func (c *ListEntitlementCommand) Execute(_ []string) error {
	cfclient := genClient(c.Api)
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	if !c.InJson {
		messages.Printf("Getting entitlements security groups as %s...\n", messages.C.Cyan(username))
	}
	cEntitlements, err := cfclient.GetSecGroupEntitlements()
	if err != nil {
		return err
	}
	entitlements, err := entitlementsExtract(cfclient, cEntitlements)
	if err != nil {
		return err
	}
	if !c.InJson {
		messages.Println(messages.C.Green("OK\n"))
	}

	if c.InJson {
		b, _ := json.MarshalIndent(entitlements, "", "\t")
		messages.Println(string(b))
		return nil
	}
	if len(entitlements) == 0 {
		return nil
	}
	data := make([][]string, 0)
	for _, entitlement := range entitlements {
		subData := []string{
			entitlement.Name,
			strings.Join(entitlement.Orgs, " "),
		}
		data = append(data, subData)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"name", "orgs"})
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
	desc := `List current security groups entitlements`
	_, err := parser.AddCommand(
		"entitlement-security-groups",
		desc,
		desc,
		&listEntitlementCommand)
	if err != nil {
		panic(err)
	}
}
