package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
)

const (
	adminScope = "cloud_controller.admin"
)

type Client struct {
	endpoint    string
	ccv3Client  *ccv3.Client
	accessToken string
}

func NewClient(endpoint string, ccv3Client *ccv3.Client, accessToken string) *Client {
	return &Client{endpoint: endpoint, ccv3Client: ccv3Client, accessToken: accessToken}
}

func (c Client) CurrentUserIsAdmin() (bool, error) {

	//token := c.session.ConfigStore().AccessToken()
	//token := c.ccv3Client.Login() // error ici
	token := c.accessToken

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
