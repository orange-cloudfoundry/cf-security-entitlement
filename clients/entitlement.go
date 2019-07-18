package clients

import (
	"bytes"
	"encoding/json"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"net/http"
)

func (c Client) EntitleSecurityGroup(secGroupGUID, orgGUID string) error {
	b, _ := json.Marshal(model.EntitlementSecGroup{
		OrganizationGUID:  orgGUID,
		SecurityGroupGUID: secGroupGUID,
	})

	req, err := http.NewRequest(http.MethodPost, c.endpoint+"/v2/security_entitlement", bytes.NewBuffer(b))
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

func (c Client) RevokeSecurityGroup(secGroupGUID, orgGUID string) error {
	b, _ := json.Marshal(model.EntitlementSecGroup{
		OrganizationGUID:  orgGUID,
		SecurityGroupGUID: secGroupGUID,
	})

	req, err := http.NewRequest(http.MethodDelete, c.endpoint+"/v2/security_entitlement", bytes.NewBuffer(b))
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

func (c Client) ListSecGroupEntitlements() ([]model.EntitlementSecGroup, error) {
	entitlements := make([]model.EntitlementSecGroup, 0)
	req, err := http.NewRequest(http.MethodGet, c.endpoint+"/v2/security_entitlement", nil)
	if err != nil {
		return entitlements, err
	}
	// cfclient do check status code and set error if >= 400
	resp, err := c.cfClient.Do(req)
	if err != nil {
		return entitlements, err
	}
	defer resp.Body.Close()
	if err != nil {
		return entitlements, err
	}

	err = json.NewDecoder(resp.Body).Decode(&entitlements)
	if err != nil {
		return entitlements, err
	}
	return entitlements, nil
}

func (c Client) OrgGUIDFromSpaceGUID(spaceGuid string) (string, error) {
	s, err := c.cfClient.GetSpaceByGuid(spaceGuid)
	if err != nil {
		return "", err
	}
	return s.OrganizationGuid, nil
}
