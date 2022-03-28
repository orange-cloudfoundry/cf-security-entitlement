package main

import (
	"encoding/json"
	"fmt"
	"strings"

	plugin_models "code.cloudfoundry.org/cli/plugin/models"
	clients "github.com/cloudfoundry-community/go-cf-clients-helper/v2"
	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
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
		"/v3/organizations/"+orgId,
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

func getOrgSpaces(orgId string) ([]plugin_models.GetOrg_Space, error) {
	orgName, err := getOrgName(orgId)
	org, err := cliConnection.GetOrg(orgName)
	if err != nil {
		return org.Spaces, err
	}
	return org.Spaces, nil
}

// a supprimer
func getOrgSpacesByPage(orgId string, pageNumber int) ([]plugin_models.GetOrg_Space, int, error) {
	result, err := cliConnection.CliCommandWithoutTerminalOutput(
		"curl",
		fmt.Sprintf("/v2/organizations/%s/spaces?order-direction=asc&page=%d&results-per-page=50", orgId, pageNumber),
	)
	if err != nil {
		return []plugin_models.GetOrg_Space{}, 0, err
	}
	var resource struct {
		TotalPages int `json:"total_pages"`
		Resources  []struct {
			Metadata struct {
				Guid string `json:"guid"`
			} `json:"metadata"`
			Entity struct {
				Name string `json:"name"`
			} `json:"entity"`
		} `json:"resources"`
	}
	err = json.Unmarshal([]byte(joinResult(result)), &resource)
	if err != nil {
		return []plugin_models.GetOrg_Space{}, 0, err
	}
	spaces := make([]plugin_models.GetOrg_Space, len(resource.Resources))
	for i, elem := range resource.Resources {
		spaces[i] = plugin_models.GetOrg_Space{
			Guid: elem.Metadata.Guid,
			Name: elem.Entity.Name,
		}
	}
	return spaces, resource.TotalPages, nil
}

func joinResult(result []string) string {
	return strings.Join(result, "\n")
}

func genClient(endpoint string) *client.Client {
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
	session, err := clients.NewSession(clients.Config{
		Endpoint:          apiUrl,
		SkipSslValidation: sslDisable,
		Token:             accessToken,
	})
	if err != nil {
		messages.Fatal(err.Error())
		return nil
	}

	return client.NewClient(endpoint, session)
}
