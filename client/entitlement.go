package client

import (
	"bytes"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"encoding/json"
	"net/http"

	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/pkg/errors"
)

func (c *Client) EntitleSecurityGroup(secGroupGUID, orgGUID string) error {
	b, _ := json.Marshal(model.EntitlementSecGroup{
		OrganizationGUID:  orgGUID,
		SecurityGroupGUID: secGroupGUID,
	})

	client := &http.Client{Transport: &c.transport}
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

	client := &http.Client{Transport: &c.transport}

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

func (c *Client) GetSecGroupEntitlements() ([]model.EntitlementSecGroup, error) {

	var entitlements []model.EntitlementSecGroup

	buffer, err := c.doRequest(http.MethodGet, c.generateUrl(c.endpoint+"/v2/security_entitlement", []ccv3.Query{}, 0), nil)
	if err = json.Unmarshal(buffer, &entitlements); err != nil {
		return entitlements, errors.Wrap(err, "Error unmarshaling entitlements")
	}
	return entitlements, nil
}
