package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/pkg/errors"
)

func (c Client) EntitleSecurityGroup(secGroupGUID, orgGUID string) error {
	// b, _ := json.Marshal(model.EntitlementSecGroup{
	// 	OrganizationGUID:  orgGUID,
	// 	SecurityGroupGUID: secGroupGUID,
	// })

	// client := &http.Client{}

	_, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"POST",
		fmt.Sprintf("%s/v2/security_entitlement", c.endpoint),
		http.Header{},
		nil,
	)
	if err != nil {
		return err
	}

	if httpres.StatusCode != http.StatusOK {
		return fmt.Errorf("http error")
	}

	// req, err := http.NewRequest(http.MethodPost, c.endpoint+"/v2/security_entitlement", bytes.NewBuffer(b))
	// if err != nil {
	// 	return err
	// }
	// req.Header.Add("Authorization", c.ccv3Client.OAuthClient())
	// resp, err := client.Do(req)
	// if err != nil {
	// 	return err
	// }

	// defer resp.Body.Close()
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (c Client) RevokeSecurityGroup(secGroupGUID, orgGUID string) error {
	// b, _ := json.Marshal(model.EntitlementSecGroup{
	// 	OrganizationGUID:  orgGUID,
	// 	SecurityGroupGUID: secGroupGUID,
	// })

	// client := &http.Client{}

	_, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"DELETE",
		fmt.Sprintf("%s/v2/security_entitlement", c.endpoint),
		http.Header{},
		nil,
	)
	if err != nil {
		return err
	}

	if httpres.StatusCode != http.StatusOK {
		return fmt.Errorf("http error")
	}

	// req, err := http.NewRequest(http.MethodDelete, c.endpoint+"/v2/security_entitlement", bytes.NewBuffer(b))
	// if err != nil {
	// 	return err
	// }
	// // need ?
	// req.Header.Add("Authorization", c.ccv3Client.OAuthClient())
	// resp, err := client.Do(req)
	// if err != nil {
	// 	return err
	// }

	// defer resp.Body.Close()
	// if err != nil {
	// 	return err
	// }

	return nil
}

func (c Client) ListSecGroupEntitlements() ([]model.EntitlementSecGroup, error) {
	entitlements := make([]model.EntitlementSecGroup, 0)
	// client := &http.Client{}
	// req, err := http.NewRequest(http.MethodGet, c.endpoint+"/v2/security_entitlement", nil)
	// if err != nil {
	// 	return entitlements, err
	// }

	// req.Header.Add("Authorization", c.ccv3Client.OAuthClient())
	// resp, err := client.Do(req)
	// if err != nil {
	// 	return entitlements, err
	// }
	// defer resp.Body.Close()
	// if err != nil {
	// 	return entitlements, err
	// }

	// err = json.NewDecoder(resp.Body).Decode(&entitlements)
	// if err != nil {
	// 	return entitlements, err
	// }

	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v2/security_entitlement", c.ccv3Client.CloudControllerURL),
		http.Header{},
		nil,
	)
	if err != nil {
		return entitlements, err
	}

	if httpres.StatusCode != http.StatusOK {
		return entitlements, fmt.Errorf("http error")
	}

	if err = json.Unmarshal(res, &entitlements); err != nil {
		return entitlements, errors.Wrap(err, "Error unmarshaling entitlements")
	}

	return entitlements, nil
}

func (c Client) OrgGUIDFromSpaceGUID(spaceGuid string) (string, error) {

	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v3/spaces/%s", c.ccv3Client.CloudControllerURL, spaceGuid),
		http.Header{},
		nil,
	)
	if err != nil {
		return spaceGuid, err
	}

	if httpres.StatusCode != http.StatusOK {
		return spaceGuid, fmt.Errorf("http error")
	}
	var space Space
	if err = json.Unmarshal(res, &space); err != nil {
		return spaceGuid, errors.Wrap(err, "Error unmarshaling Space")
	}
	return space.Relationships["organization"].GUID, nil

}
