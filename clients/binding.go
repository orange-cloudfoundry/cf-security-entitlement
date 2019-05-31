package clients

import (
	"fmt"
	"net/http"
)

func (c Client) BindSecurityGroup(secGroupGUID, spaceGUID string) error {

	endpoint := fmt.Sprintf("%s/v2/security_groups/%s/spaces/%s",
		c.endpoint,
		secGroupGUID,
		spaceGUID,
	)
	req, err := http.NewRequest(http.MethodPut, endpoint, nil)
	if err != nil {
		return err
	}
	// cfclient do check status code and set error if >= 400
	resp, err := c.cfClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func (c Client) UnbindSecurityGroup(secGroupGUID, spaceGUID string) error {

	endpoint := fmt.Sprintf("%s/v2/security_groups/%s/spaces/%s",
		c.endpoint,
		secGroupGUID,
		spaceGUID,
	)
	req, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return err
	}
	// cfclient do check status code and set error if >= 400
	resp, err := c.cfClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}
