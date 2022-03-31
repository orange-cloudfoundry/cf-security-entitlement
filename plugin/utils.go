package main

import (
	"encoding/json"
	"fmt"
	"strings"

	plugin_models "code.cloudfoundry.org/cli/plugin/models"
	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
	"code.cloudfoundry.org/cli/util/configv3"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/cli/api/uaa"
	ccWrapper "code.cloudfoundry.org/cli/api/cloudcontroller/wrapper"
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

	sslDisable, _ := cliConnection.IsSSLDisabled()

	config := &configv3.Config{
		ConfigFile: configv3.JSONConfig{
			ConfigVersion:        3,
			Target:               apiUrl,
			AccessToken:          accessToken,
			SkipSSLValidation:    sslDisable,
		},
	}

	uaaClient := uaa.NewClient(config)
	authWrapperV3 := ccWrapper.NewUAAAuthentication(uaaClient, config)
	ccWrappersV3 := []ccv3.ConnectionWrapper{
		authWrapperV3,
		ccWrapper.NewRetryRequest(config.RequestRetryCount()),
	}

	ccClientV3 := ccv3.NewClient(ccv3.Config{
		AppName:            config.BinaryName(),
		AppVersion:         config.BinaryVersion(),
		JobPollingTimeout:  config.OverallPollingTimeout(),
		JobPollingInterval: config.PollingInterval(),
		Wrappers:           ccWrappersV3,
	})

	ccClientV3.TargetCF(ccv3.TargetSettings{
		URL:               config.Target(),
		SkipSSLValidation: config.SkipSSLValidation(),
		DialTimeout:       config.DialTimeout(),
	})

	info, _, err := ccClientV3.GetInfo()
	if err != nil {
		messages.Error(err.Error())
		return nil
	}

	return client.NewClient(endpoint, ccClientV3)
}
