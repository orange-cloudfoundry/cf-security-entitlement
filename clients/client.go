package clients

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudfoundry-community/go-cfclient"
	"strings"
)

const (
	adminScope = "cloud_controller.admin"
)

type Client struct {
	endpoint string
	cfClient *cfclient.Client
}

func NewClient(endpoint string, cfClient *cfclient.Client) *Client {
	return &Client{endpoint: endpoint, cfClient: cfClient}
}

func (c Client) CurrentUserIsAdmin() (bool, error) {
	token, err := c.cfClient.GetToken()
	if err != nil {
		return false, err
	}

	tokenSplit := strings.Split(token, ".")
	if len(tokenSplit) < 3 {
		return false, fmt.Errorf("not a jwt")
	}

	b, err := base64.RawStdEncoding.DecodeString(tokenSplit[1])
	if err != nil {
		return false, err
	}

	scopeS := struct {
		Scopes []string `json:"scope"`
	}{}

	err = json.Unmarshal(b, &scopeS)
	if err != nil {
		return false, err
	}

	for _, scope := range scopeS.Scopes {
		if scope == adminScope {
			return true, nil
		}
	}
	return false, nil
}
