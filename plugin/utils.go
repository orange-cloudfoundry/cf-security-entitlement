package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	ccWrapper "code.cloudfoundry.org/cli/api/cloudcontroller/wrapper"
	"code.cloudfoundry.org/cli/api/uaa"
	plugin_models "code.cloudfoundry.org/cli/plugin/models"
	"code.cloudfoundry.org/cli/util/configv3"
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
		Name string `json:"name"`
	}
	err = json.Unmarshal([]byte(joinResult(result)), &org)
	if err != nil {
		return "", err
	}
	if org.Name == "" {
		return "", fmt.Errorf("Org %s not found", orgId)
	}
	return org.Name, nil
}

func getOrgSpaces(orgId string) ([]plugin_models.GetOrg_Space, error) {
	orgName, err := getOrgName(orgId)
	org, err := cliConnection.GetOrg(orgName)
	if err != nil {
		return org.Spaces, err
	}
	return org.Spaces, nil
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
			ConfigVersion:     3,
			Target:            apiUrl,
			AccessToken:       accessToken,
			SkipSSLValidation: sslDisable,
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

	//info, _, err := ccClientV3.GetInfo()

	if err != nil {
		messages.Error(err.Error())
		return nil
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: sslDisable},
	}

	return client.NewClient(endpoint, ccClientV3, accessToken, apiUrl, *tr)
}
