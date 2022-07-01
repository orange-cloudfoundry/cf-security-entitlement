package client

import (
	"bytes"
	"net/http"
)

func (c Client) BindSecurityGroup(secGroupGUID, spaceGUID string, endpoint string) error {

	err := c.BindRunningSecGroupToSpace(secGroupGUID, spaceGUID, endpoint)
	if err != nil {
		return err
	}

	err = c.BindStagingSecGroupToSpace(secGroupGUID, spaceGUID, endpoint)
	if err != nil {
		return err
	}

	return nil
}

func (c Client) UnBindSecurityGroup(secGroupGUID, spaceGUID string, endpoint string) error {

	err := c.UnBindRunningSecGroupToSpace(secGroupGUID, spaceGUID, endpoint)
	if err != nil {
		return err
	}

	err = c.UnBindStagingSecGroupToSpace(secGroupGUID, spaceGUID, endpoint)
	if err != nil {
		return err
	}

	return nil
}

func (c Client) BindRunningSecGroupToSpace(secGroupGUID, spaceGUID string, endpoint string) error {
	var jsonData = []byte(`{"data":[
		{"guid":"` + spaceGUID + `"}
		]
	}`)

	client := &http.Client{Transport: &c.transport}
	url := endpoint + "/v3/security_groups/" + secGroupGUID + "/relationships/running_spaces"
	Request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))

	Request.Header.Add("Authorization", c.accessToken)
	Request.Header.Add("Content-type", "application/json")
	resp, err := client.Do(Request)
	if err != nil {
		return err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		return err
	}

	defer resp.Body.Close()

	return nil
}

func (c Client) BindStagingSecGroupToSpace(secGroupGUID, spaceGUID string, endpoint string) error {
	var jsonData = []byte(`{"data":[
		{"guid":"` + spaceGUID + `"}
		]
	}`)

	client := &http.Client{Transport: &c.transport}
	url := endpoint + "/v3/security_groups/" + secGroupGUID + "/relationships/staging_spaces"
	Request, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(jsonData))

	Request.Header.Add("Authorization", c.accessToken)
	Request.Header.Add("Content-type", "application/json")
	resp, err := client.Do(Request)
	if err != nil {
		return err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		_, err := c.handleError(resp)
		return err
	}

	defer resp.Body.Close()

	return nil
}

func (c Client) UnBindRunningSecGroupToSpace(secGroupGUID, spaceGUID string, endpoint string) error {

	client := &http.Client{Transport: &c.transport}
	url := endpoint + "/v3/security_groups/" + secGroupGUID + "/relationships/running_spaces/" + spaceGUID
	Request, err := http.NewRequest(http.MethodDelete, url, nil)
	Request.Header.Add("Authorization", c.accessToken)
	Request.Header.Add("Content-type", "application/json")
	resp, err := client.Do(Request)
	if err != nil {
		return err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		_, err := c.handleError(resp)
		return err

	}

	defer resp.Body.Close()

	return nil
}

func (c Client) UnBindStagingSecGroupToSpace(secGroupGUID, spaceGUID string, endpoint string) error {

	client := &http.Client{Transport: &c.transport}
	url := endpoint + "/v3/security_groups/" + secGroupGUID + "/relationships/staging_spaces/" + spaceGUID
	Request, err := http.NewRequest(http.MethodDelete, url, nil)

	Request.Header.Add("Authorization", c.accessToken)
	Request.Header.Add("Content-type", "application/json")
	resp, err := client.Do(Request)
	if err != nil {
		return err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		_, err := c.handleError(resp)
		return err
	}

	defer resp.Body.Close()

	return nil
}
