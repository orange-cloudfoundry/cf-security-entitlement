package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/cli/resources"
	"github.com/pkg/errors"
)

type Space struct {
	GUID          string                  `json:"guid,omitempty"`
	Name          string                  `json:"name"`
	CreatedAt     string                  `json:"created_at"`
	UpdatedAt     string                  `json:"updated_at"`
	Relationships resources.Relationships `json:"relationships,omitempty"`
}

type Organization struct {
	GUID      string `json:"guid,omitempty"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
	QuotaGUID string `json:"-"`
}

type Resources struct {
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
			Data []struct {
				GUID      string `jsonry:"guid,omitempty"`
				SpaceName string
				OrgGuid   string
				OrgName   string
			}
		}
		Staging_spaces struct {
			Data []struct {
				GUID      string `jsonry:"guid,omitempty"`
				SpaceName string
				OrgGuid   string
				OrgName   string
			}
		}
	}
}

type SecurityGroup struct {
	Resources []Resources
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

func (c Client) ListSecGroups(query ...ccv3.Query) ([]SecurityGroup, error) {

	SecGroup := []SecurityGroup{}
	_, _, err := c.ccv3Client.MakeListRequest(ccv3.RequestParams{
		RequestName:  "GetSecurityGroupsRequest",
		Query:        query,
		ResponseBody: SecurityGroup{},
		AppendToList: func(item interface{}) error {
			SecGroup = append(SecGroup, item.(SecurityGroup))
			return nil
		},
	})

	return SecGroup, err

}

func (c Client) GetSecGroupByName(name string) (SecurityGroup, error) {
	var SecGroup SecurityGroup

	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v3/security_groups?names=%s", c.ccv3Client.CloudControllerURL, name),
		http.Header{},
		nil,
	)
	if err != nil {
		return SecGroup, err
	}
	if httpres.StatusCode != http.StatusOK {
		return SecGroup, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(res, &SecGroup); err != nil {
		return SecGroup, errors.Wrap(err, "Error unmarshaling security group")
	}

	SecGroupRelation, err := c.GetSecGroupRelationships(SecGroup)
	if err != nil {
		return SecGroupRelation, err
	}

	return SecGroupRelation, nil
}

func (c Client) GetSecGroupByGuid(guid string) (SecurityGroup, error) {

	var SecGroup SecurityGroup

	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v3/security_groups/%s", c.ccv3Client.CloudControllerURL, guid),
		http.Header{},
		nil,
	)
	if err != nil {
		return SecGroup, err
	}

	if httpres.StatusCode != http.StatusOK {
		return SecGroup, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(res, &SecGroup); err != nil {
		return SecGroup, errors.Wrap(err, "Error unmarshaling security group")
	}

	SecGroupRelation, err := c.GetSecGroupRelationships(SecGroup)
	if err != nil {
		return SecGroupRelation, err
	}

	return SecGroupRelation, nil
}

func (c Client) GetSecGroupSpaces(guid string) ([]string, error) {
	spacesGuid := make([]string, 0)

	_, err := c.GetSecGroupByGuid(guid)
	if err != nil {
		return spacesGuid, err
	}

	return spacesGuid, nil
}

func (c Client) GetOrgByGuid(guid string) (Organization, error) {

	org := Organization{}
	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v3/organizations/%s", c.ccv3Client.CloudControllerURL, guid),
		http.Header{},
		nil,
	)
	if err != nil {
		return org, err
	}

	if httpres.StatusCode != http.StatusOK {
		return org, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(res, &org); err != nil {
		return org, errors.Wrap(err, "Error unmarshaling Org")
	}
	return org, nil
}

func (c Client) GetSpaceByGuid(guid string) (Space, error) {
	var space Space

	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v3/spaces/%s", c.ccv3Client.CloudControllerURL, guid),
		http.Header{},
		nil,
	)
	if err != nil {
		return space, err
	}

	if httpres.StatusCode != http.StatusOK {
		return space, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(res, &space); err != nil {
		return space, errors.Wrap(err, "Error unmarshaling Space")
	}
	return space, nil
}

func (c Client) GetSecGroupRelationships(SecGroup SecurityGroup) (SecurityGroup, error) {
	x := 0
	for _, spaceGuid := range SecGroup.Resources[0].Relationships.Running_spaces.Data {
		Space, err := c.GetSpaceByGuid(spaceGuid.GUID)
		if err != nil {
			return SecGroup, err
		}

		SecGroup.Resources[0].Relationships.Running_spaces.Data[x].SpaceName = Space.Name
		SecGroup.Resources[0].Relationships.Running_spaces.Data[x].OrgGuid = Space.Relationships["organization"].GUID
		Org, _, _ := c.ccv3Client.GetOrganization(Space.Relationships["organization"].GUID)
		SecGroup.Resources[0].Relationships.Running_spaces.Data[x].OrgName = Org.Name
		x++
	}

	for _, spaceGuid := range SecGroup.Resources[0].Relationships.Staging_spaces.Data {
		Space, err := c.GetSpaceByGuid(spaceGuid.GUID)
		if err != nil {
			return SecGroup, err
		}
		SecGroup.Resources[0].Relationships.Staging_spaces.Data[x].SpaceName = Space.Name
		SecGroup.Resources[0].Relationships.Staging_spaces.Data[x].OrgGuid = Space.Relationships["organization"].GUID
		Org, _, _ := c.ccv3Client.GetOrganization(Space.Relationships["organization"].GUID)
		SecGroup.Resources[0].Relationships.Staging_spaces.Data[x].OrgName = Org.Name
		x++
	}

	return SecGroup, nil
}

func (c Client) ListUserManagedOrgs(userGuid string) (UserRoles, error) {
	userRoles := UserRoles{}

	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v3/roles?user_guids=%s", c.ccv3Client.CloudControllerURL, userGuid),
		http.Header{},
		nil,
	)
	if err != nil {
		return userRoles, err
	}

	if httpres.StatusCode != http.StatusOK {
		return userRoles, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(res, &userRoles); err != nil {
		return userRoles, errors.Wrap(err, "Error unmarshaling User Roles")
	}
	return userRoles, nil
}

func (c Client) ListOrgManagers(orgGuid string) (User, error) {
	user := User{}

	res, httpres, err := c.ccv3Client.MakeRequestSendReceiveRaw(
		"GET",
		fmt.Sprintf("%s/v3/roles?organization_guids=%s", c.ccv3Client.CloudControllerURL, orgGuid),
		http.Header{},
		nil,
	)
	if err != nil {
		return user, err
	}

	if httpres.StatusCode != http.StatusOK {
		return user, fmt.Errorf("http error")
	}
	if err = json.Unmarshal(res, &user); err != nil {
		return user, errors.Wrap(err, "Error unmarshaling User")
	}
	return user, nil
}
