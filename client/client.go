package client

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	clients "github.com/cloudfoundry-community/go-cf-clients-helper/v2"
)

const (
	adminScope = "cloud_controller.admin"
)

type Client struct {
	endpoint string
	session  *clients.Session
}

func NewClient(endpoint string, session *clients.Session) *Client {
	return &Client{endpoint: endpoint, session: session}
}

func (c Client) CurrentUserIsAdmin() (bool, error) {

	token := c.session.ConfigStore().AccessToken()

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
