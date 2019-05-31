package clients

import (
	"github.com/cloudfoundry-community/go-cfclient"
	"net/http"
)

type Client struct {
	endpoint string
	cfClient *cfclient.Client
}

func NewClient(endpoint string, cfClient *cfclient.Client) *Client {
	return &Client{endpoint: endpoint, cfClient: cfClient}
}
func (c Client) setToken(req *http.Request) error {
	token, err := c.cfClient.GetToken()
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", token)
	return nil
}
