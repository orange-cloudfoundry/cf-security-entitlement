package main

import (
	"code.cloudfoundry.org/cli/plugin/models"
	"encoding/json"
	"fmt"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/orange-cloudfoundry/cf-security-entitlement/clients"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
	"strings"
)

func getOrgID(orgName string) (string, error) {
	org, err := cliConnection.GetOrg(orgName)
	if err != nil {
		return "", err
	}

	return org.Guid, nil
}

func getOrgName(orgId string) (string, error) {
	result, err := cliConnection.CliCommandWithoutTerminalOutput(
		"curl",
		"/v2/organizations/"+orgId,
	)
	if err != nil {
		return "", err
	}
	var org struct {
		Entity struct {
			Name string `json:"name"`
		} `json:"entity"`
	}
	err = json.Unmarshal([]byte(joinResult(result)), &org)
	if err != nil {
		return "", err
	}
	if org.Entity.Name == "" {
		return "", fmt.Errorf("Org %s not found", orgId)
	}
	return org.Entity.Name, nil
}

func getOrgSpaces(orgName string) ([]plugin_models.GetOrg_Space, error) {
	org, err := cliConnection.GetOrg(orgName)
	if err != nil {
		return []plugin_models.GetOrg_Space{}, err
	}

	return org.Spaces, nil
}

func joinResult(result []string) string {
	return strings.Join(result, "\n")
}

func genClient(endpoint string) *clients.Client {
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	apiUrl, err := cliConnection.ApiEndpoint()
	if err != nil {
		messages.Error(err.Error())
		return nil
	}
	accessToken, err := cliConnection.AccessToken()
	if err != nil {
		messages.Fatal(err.Error())
	}
	accessToken = strings.TrimPrefix(accessToken, "bearer ")
	sslDisable, _ := cliConnection.IsSSLDisabled()
	cfClient, err := cfclient.NewClient(&cfclient.Config{
		ApiAddress:        apiUrl,
		SkipSslValidation: sslDisable,
		Token:             accessToken,
	})
	if err != nil {
		messages.Fatal(err.Error())
		return nil
	}

	return clients.NewClient(endpoint, cfClient)
}
