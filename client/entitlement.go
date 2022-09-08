package client

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/pkg/errors"
)

func (c *Client) EntitleSecurityGroup(secGroupGUID, orgGUID string) error {
	b, _ := json.Marshal(model.EntitlementSecGroup{
		OrganizationGUID:  orgGUID,
		SecurityGroupGUID: secGroupGUID,
	})

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/v2/security_entitlement", bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", c.accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		_, err := c.handleError(resp)
		return err
	}

	defer resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) RevokeSecurityGroup(secGroupGUID, orgGUID string) error {
	b, _ := json.Marshal(model.EntitlementSecGroup{
		OrganizationGUID:  orgGUID,
		SecurityGroupGUID: secGroupGUID,
	})

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodDelete, c.endpoint+"/v2/security_entitlement", bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", c.accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		_, err := c.handleError(resp)
		return err
	}

	defer resp.Body.Close()
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) ListSecGroupEntitlements() ([]model.EntitlementSecGroup, error) {

	entitlements := make([]model.EntitlementSecGroup, 0)

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/v2/security_entitlement", nil)
	if err != nil {
		return entitlements, err
	}

	req.Header.Add("Authorization", c.accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return entitlements, err
	}
	defer resp.Body.Close()
	if err != nil {
		return entitlements, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		_, err := c.handleError(resp)
		return entitlements, err
	}

	err = json.NewDecoder(resp.Body).Decode(&entitlements)
	if err != nil {
		return entitlements, err
	}
	return entitlements, nil
}

func (c *Client) OrgGUIDFromSpaceGUID(spaceGuid string) (string, error) {

	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/v3/spaces/"+spaceGuid, nil)
	if err != nil {
		return spaceGuid, err
	}

	req.Header.Add("Authorization", c.accessToken)
	resp, err := client.Do(req)
	if err != nil {
		return spaceGuid, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return spaceGuid, err
	}
	var space Space
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return spaceGuid, err
	}
	if err = json.Unmarshal(buf, &space); err != nil {
		return spaceGuid, errors.Wrap(err, "Error unmarshaling Space")
	}
	return space.Relationships["organization"].GUID, nil

}
