package main

import (
	"bytes"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"fmt"
	"github.com/olekukonko/tablewriter"
	client2 "github.com/orange-cloudfoundry/cf-security-entitlement/v2/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/plugin/messages"
	"net"
	"os"
	"strconv"
	"strings"
)

type SearchOptions struct {
	Ip   string `positional-arg-name:"IP" required:"true"`
	Port string `positional-arg-name:"PORT"`
}

type SearchCommand struct {
	Api           string        `short:"a" long:"api" description:"api to cf security"`
	SearchOptions SearchOptions `positional-args:"true"`
}

var searchCommand SearchCommand

func (c *SearchCommand) Execute(_ []string) error {
	client := genClient(c.Api)
	username, err := cliConnection.Username()
	if err != nil {
		return err
	}
	// Parse IP and port
	searchedIp := net.ParseIP(c.SearchOptions.Ip)
	searchedPort, err := strconv.Atoi(c.SearchOptions.Port)
	if err != nil {
		searchedPort = 0
	}

	// Show header message
	text := fmt.Sprintf("Searching security groups for %s", messages.C.Cyan(searchedIp))
	if searchedPort > 0 {
		text = fmt.Sprintf("%s and port %s", text, messages.C.Cyan(fmt.Sprintf("%d", searchedPort)))
	}
	_, _ = messages.Printf("%s as %s...\n", text, messages.C.Cyan(username))

	// Get security groups
	secGroups, err := client.GetSecGroups([]ccv3.Query{}, 0)
	if err != nil {
		return err
	}

	// Match IP
	matchedIpSecGroups := make([]client2.SecurityGroup, 0)
	for _, secGroup := range secGroups.Resources {
		for _, rule := range secGroup.Rules {
			matched := false
			for _, destination := range strings.Split(rule.Destination, ",") {
				_, ipNet, err := net.ParseCIDR(destination)
				if err == nil {
					if ipNet.Contains(searchedIp) {
						matchedIpSecGroups = append(matchedIpSecGroups, secGroup)
						matched = true
						break
					}
				} else {
					ips := strings.Split(destination, "-")
					if len(ips) == 2 {
						startIp := net.ParseIP(ips[0])
						endIp := net.ParseIP(ips[1])
						if bytes.Compare(searchedIp, startIp) >= 0 && bytes.Compare(searchedIp, endIp) <= 0 {
							matchedIpSecGroups = append(matchedIpSecGroups, secGroup)
							matched = true
							break
						}
					} else {
						if searchedIp.Equal(net.ParseIP(destination)) {
							matchedIpSecGroups = append(matchedIpSecGroups, secGroup)
							matched = true
							break
						}
					}
				}
			}
			if matched {
				break
			}
		}
	}

	// Match port
	var matchedSecGroups []client2.SecurityGroup
	if searchedPort > 0 {
		matchedSecGroups = make([]client2.SecurityGroup, 0)
		for _, secGroup := range matchedIpSecGroups {
			for _, rule := range secGroup.Rules {
				matched := false
				for _, destination := range strings.Split(rule.Ports, ",") {
					if destination == "" {
						matchedSecGroups = append(matchedSecGroups, secGroup)
						matched = true
						break
					}
					if destination == fmt.Sprintf("%d", searchedPort) {
						matchedSecGroups = append(matchedSecGroups, secGroup)
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
		}
	} else {
		matchedSecGroups = matchedIpSecGroups
	}

	// Show result
	_, _ = messages.Println(messages.C.Green("OK\n"))

	if len(matchedSecGroups) == 0 {
		return nil
	}

	// Show table
	data := make([][]string, 0)
	for iSec, secGroup := range matchedSecGroups {
		subData := make([]string, 0)
		subData = append(subData, fmt.Sprintf("#%d", iSec), secGroup.Name)
		nbLines := 0
		for _, rule := range secGroup.Rules {
			for _, destination := range strings.Split(rule.Destination, ",") {
				for _, port := range strings.Split(rule.Ports, ",") {
					if nbLines > 0 {
						subData = make([]string, 0)
						subData = append(subData, "", "")
					}
					subData = append(subData, destination, port)
					data = append(data, subData)
					nbLines++
				}
			}
		}
	}

	text = fmt.Sprintf("Found %s security-group(s) for destination %s", messages.C.Cyan(fmt.Sprintf("%d", len(matchedSecGroups))), messages.C.Cyan(searchedIp))
	if searchedPort > 0 {
		text = fmt.Sprintf("%s and port %s", text, messages.C.Cyan(fmt.Sprintf("%d", searchedPort)))
	}
	_, _ = messages.Println(text)
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("#", "Name", "Destination", "Port")
	table.Bulk(data)
	table.Render()
	return nil
}

func init() {
	desc := `Search IP in security groups`
	_, err := parser.AddCommand(
		"manager-search-security-groups",
		desc,
		desc,
		&searchCommand)
	if err != nil {
		panic(err)
	}
}
