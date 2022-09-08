package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/cli/resources"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/pkg/errors"
)

type Spaces struct {
	Resources []Space `json:"resources"`
}

type Space struct {
	GUID          string                  `json:"guid,omitempty"`
	Name          string                  `json:"name"`
	CreatedAt     string                  `json:"created_at"`
	UpdatedAt     string                  `json:"updated_at"`
	Relationships resources.Relationships `json:"relationships,omitempty"`
}

type Data struct {
	GUID      string `jsonry:"guid,omitempty"`
	SpaceName string `json:"spacename,omitempty"`
	OrgGUID   string `json:"orgguid,omitempty"`
	OrgName   string `json:"orgname,omitempty"`
}

type Organization struct {
	GUID      string `json:"guid,omitempty"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	QuotaGUID string `json:"-"`
}

type SecurityGroups struct {
	Resources []SecurityGroup `jsonry:"resources,omitempty"`
}

type SecurityGroup struct {
	Name             string `jsonry:"name,omitempty"`
	GUID             string `jsonry:"guid,omitempty"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
	Rules            []Rule `jsonry:"rules,omitempty"`
	Globally_Enabled struct {
		Running bool `json:"running"`
		Staging bool `json:"staging"`
	}
	Relationships struct {
		Running_spaces struct {
			Data []Data
		}

		Staging_spaces struct {
			Data []Data
		}
	}
}
type Rule struct {
	Protocol    string `json:"protocol"`
	Destination string `json:"destination"`
	Ports       string `json:"ports,omitempty"`
}

type User struct {
	Resources []struct {
		GUID          string `jsonry:"guid,omitempty"`
		CreatedAt     string `json:"created_at"`
		UpdatedAt     string `json:"updated_at"`
		Type          string `jsonry:"type,omitempty"`
		Relationships struct {
			User struct {
				Data struct {
					GUID string `json:"guid"`
				}
			}
		}
	}
}

type UserRoles struct {
	Resources []struct {
		GUID          string `jsonry:"guid,omitempty"`
		CreatedAt     string `json:"created_at"`
		UpdatedAt     string `json:"updated_at"`
		Type          string `jsonry:"type,omitempty"`
		Relationships struct {
			User struct {
				Data struct {
					GUID string `json:"guid"`
				}
			}
			Space struct {
				Data struct {
					GUID string `json:"guid"`
				}
			}
			Organization struct {
				Data struct {
					GUID string `json:"guid"`
				}
			}
		}
	}
}

var large = ccv3.Query{
	Key:    ccv3.PerPage,
	Values: []string{"5000"},
}

var orderByTimestampDesc = ccv3.Query{
	Key:    ccv3.OrderBy,
	Values: []string{"-created_at"},
}

func (c *Client) ListSecGroups(query ...ccv3.Query) (SecurityGroups, error) {
	SecGroup := SecurityGroups{}

	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.endpoint+"/v3/security_groups", nil)
	if err != nil {
		return SecGroup, err
	}
	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return SecGroup, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return SecGroup, errors.Wrap(err, "http error")
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return SecGroup, err
	}
	if err = json.Unmarshal(buf, &SecGroup); err != nil {
		return SecGroup, errors.Wrap(err, "Error unmarshaling security group")
	}
	return SecGroup, err

}

func (c *Client) GetSecGroupByName(name string) (SecurityGroup, error) {
	var SecGroup SecurityGroups
	var errorSecGroup SecurityGroup

	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.endpoint+"/v3/security_groups?names="+name, nil)
	if err != nil {
		return errorSecGroup, err
	}
	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return errorSecGroup, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errorSecGroup, err
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errorSecGroup, err
	}

	if err = json.Unmarshal(buf, &SecGroup); err != nil {
		return errorSecGroup, errors.Wrap(err, "Error unmarshaling security group")
	}

	if len(SecGroup.Resources) == 0 {
		return errorSecGroup, fmt.Errorf("No security group with name %v found", name)
	}

	SecGroupRelation, err := c.ListSpaceResources(SecGroup.Resources[0])
	if err != nil {
		return SecGroupRelation, err
	}

	return SecGroupRelation, nil
}

func (c *Client) GetSecGroupByGuid(guid string) (SecurityGroup, error) {
	var SecGroup SecurityGroup

	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.apiUrl+"/v3/security_groups/"+guid, nil)
	if err != nil {
		return SecGroup, err
	}
	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return SecGroup, err
	}

	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return SecGroup, err
	}
	if err = json.Unmarshal(buf, &SecGroup); err != nil {
		return SecGroup, errors.Wrap(err, "Error unmarshaling Security Group")
	}

	SecGroupRelation, err := c.ListSpaceResources(SecGroup)
	if err != nil {
		return SecGroupRelation, err
	}

	return SecGroupRelation, nil
}

func (c *Client) GetOrgByGuid(guid string) (Organization, error) {

	org := Organization{}

	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.apiUrl+"/v3/organizations/"+guid, nil)
	if err != nil {
		return org, err
	}
	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return org, err
	}

	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return org, err
	}

	if resp.StatusCode != http.StatusOK {
		return org, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(buf, &org); err != nil {
		return org, errors.Wrap(err, "Error unmarshaling Org")
	}
	return org, nil
}

func (c *Client) GetSpaceByGuid(guid string) (Space, error) {
	var space Space

	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.apiUrl+"/v3/spaces/"+guid, nil)
	if err != nil {
		return space, err
	}
	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return space, err
	}

	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return space, err
	}
	if err = json.Unmarshal(buf, &space); err != nil {
		return space, errors.Wrap(err, "Error unmarshaling Space")
	}
	return space, nil

}

func (c *Client) GetSecGroupSpaces(guid string) (Spaces, error) {
	var spaces Spaces
	var space Space

	secgroup, err := c.GetSecGroupByGuid(guid)
	if err != nil {
		return spaces, err
	}

	for _, spaceData := range secgroup.Relationships.Running_spaces.Data {
		space.GUID = spaceData.GUID
		spaces.Resources = append(spaces.Resources, space)
	}

	return spaces, nil
}

func (c *Client) ListUserManagedOrgs(userGuid string) (UserRoles, error) {
	userRoles := UserRoles{}
	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.apiUrl+"/v3/roles?user_guids="+userGuid, nil)
	if err != nil {
		return userRoles, err
	}
	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return userRoles, err
	}

	defer resp.Body.Close()
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return userRoles, err
	}

	if resp.StatusCode != http.StatusOK {
		return userRoles, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(buf, &userRoles); err != nil {
		return userRoles, errors.Wrap(err, "Error unmarshaling User Roles")
	}
	return userRoles, nil
}

func (c *Client) ListOrgManagers(orgGuid string) (User, error) {
	user := User{}
	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.apiUrl+"/v3/roles?organization_guids="+orgGuid, nil)
	if err != nil {
		return user, err
	}
	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return user, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("http error")
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return user, err
	}

	if err = json.Unmarshal(buf, &user); err != nil {
		return user, errors.Wrap(err, "Error unmarshaling User")
	}
	return user, nil
}

func (c *Client) GetInfo() (model.Info, error) {
	info := model.Info{}

	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.apiUrl, nil)
	if err != nil {
		return info, err
	}

	resp, err := client.Do(Request)
	if err != nil {
		return info, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return info, fmt.Errorf("http error")
	}
	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}

	if err = json.Unmarshal(buf, &info); err != nil {
		return info, errors.Wrap(err, "Error unmarshaling User")
	}
	return info, nil
}

func (c *Client) GetAccessToken() *string {
	return &c.accessToken
}

func (c *Client) SetAccessToken(accessToken string) {
	c.accessToken = accessToken
}

func (c *Client) GetApiUrl() string {
	return c.apiUrl
}

func (c *Client) GetEndpoint() string {
	return c.endpoint
}

func (c *Client) GetTransport() http.Transport {
	return c.transport
}

func (c *Client) ListSpaceResources(secGroup SecurityGroup) (SecurityGroup, error) {
	var spaces Spaces
	client := &http.Client{Transport: &c.transport}

	Request, err := http.NewRequest(http.MethodGet, c.apiUrl+"/v3/spaces", nil)
	if err != nil {
		return secGroup, err
	}

	Request.Header.Add("Authorization", c.accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		return secGroup, err
	}

	if resp.StatusCode >= http.StatusBadRequest {
		_, err := c.handleError(resp)
		return secGroup, err
	}

	defer resp.Body.Close()

	if err != nil {
		return secGroup, err
	}

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return secGroup, err
	}

	if err = json.Unmarshal(buf, &spaces); err != nil {
		return secGroup, err
	}

	for _, space := range spaces.Resources {
		for i, secGroupSpaceRunning := range secGroup.Relationships.Running_spaces.Data {
			if space.GUID == secGroupSpaceRunning.GUID {
				secGroup.Relationships.Running_spaces.Data[i].OrgGUID = space.Relationships["organization"].GUID
				secGroup.Relationships.Running_spaces.Data[i].SpaceName = space.Name
				org, err := c.GetOrgByGuid(space.Relationships["organization"].GUID)
				if err != nil {
					return secGroup, err
				}
				secGroup.Relationships.Running_spaces.Data[i].OrgName = org.Name
			}
		}

		for j, secGroupSpaceStaging := range secGroup.Relationships.Staging_spaces.Data {
			if space.GUID == secGroupSpaceStaging.GUID {
				secGroup.Relationships.Staging_spaces.Data[j].OrgGUID = space.Relationships["organization"].GUID
				secGroup.Relationships.Staging_spaces.Data[j].SpaceName = space.Name
				org, err := c.GetOrgByGuid(space.Relationships["organization"].GUID)
				if err != nil {
					return secGroup, err
				}
				secGroup.Relationships.Staging_spaces.Data[j].OrgName = org.Name
			}
		}
	}
	return secGroup, err
}
