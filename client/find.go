package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3/constant"
	"code.cloudfoundry.org/cli/resources"
	"github.com/pkg/errors"
)

type Spaces struct {
	Paginated
	Resources []Space                `jsonry:"resources"`
	Included  ccv3.IncludedResources `jsonry:"included"`
}

type NotFoundError error

type Space struct {
	resources.Space
}

type Data struct {
	GUID      string `jsonry:"guid,omitempty"`
	SpaceName string `jsonry:"spacename,omitempty"`
	OrgGUID   string `jsonry:"orgguid,omitempty"`
	OrgName   string `jsonry:"orgname,omitempty"`
	Running   bool   `jsonry:"runnning"`
	Staging   bool   `jsonry:"staging"`
}

type Organization struct {
	resources.Organization
}

type Organizations struct {
	Paginated
	Resources []Organization `jsonry:"resources"`
}

type Paginated struct {
	Pagination struct {
		Next struct {
			HREF string `jsonry:"href"`
		} `jsonry:"next"`
	} `jsonry:"pagination"`
}

type SecurityGroups struct {
	Paginated
	Resources []SecurityGroup `jsonry:"resources,omitempty"`
}

type SecurityGroup struct {
	Name                   string `jsonry:"name,omitempty"`
	GUID                   string `jsonry:"guid,omitempty"`
	Rules                  []Rule `jsonry:"rules,omitempty"`
	StagingGloballyEnabled *bool  `jsonry:"globally_enabled.staging,omitempty"`
	RunningGloballyEnabled *bool  `jsonry:"globally_enabled.running,omitempty"`
	Relationships          struct {
		Running_Spaces struct {
			Data []Data `jsonry:"data"`
		} `jsonry:"running_spaces"`
		Staging_Spaces struct {
			Data []Data `jsonry:"data"`
		} `jsonry:"staging_spaces"`
	} `jsonry:"relationships,omitempty"`
}
type Rule struct {
	Protocol    string `jsonry:"protocol"`
	Destination string `jsonry:"destination"`
	Ports       string `jsonry:"ports,omitempty"`
}

type User struct {
	Paginated
	Resources []struct {
		GUID          string `jsonry:"guid,omitempty"`
		CreatedAt     string `jsonry:"created_at"`
		UpdatedAt     string `jsonry:"updated_at"`
		Type          string `jsonry:"type,omitempty"`
		Relationships struct {
			User struct {
				Data struct {
					GUID string `jsonry:"guid"`
				}
			}
		}
	}
}

type UserRoles struct {
	Paginated
	Resources []struct {
		GUID          string `jsonry:"guid,omitempty"`
		CreatedAt     string `jsonry:"created_at"`
		UpdatedAt     string `jsonry:"updated_at"`
		Type          string `jsonry:"type,omitempty"`
		Relationships struct {
			User struct {
				Data struct {
					GUID string `jsonry:"guid"`
				} `jsonry:"data"`
			} `jsonry:"user"`
			Space struct {
				Data struct {
					GUID string `jsonry:"guid"`
				} `jsonry:"data"`
			} `jsonry:"space"`
			Organization struct {
				Data struct {
					GUID string `jsonry:"guid"`
				} `jsonry:"data"`
			} `jsonry:"organization"`
		} `jsonry:"relationships"`
	} `jsonry:"resources"`
}

var Large = ccv3.Query{
	Key:    ccv3.PerPage,
	Values: []string{"5000"},
}

var orderByTimestampDesc = ccv3.Query{
	Key:    ccv3.OrderBy,
	Values: []string{"-created_at"},
}

func (c *Client) doRequest(method string, url string, body io.Reader) ([]byte, error) {
	client := &http.Client{Transport: &c.transport}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Authorization", c.accessToken)
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.Wrap(err, "http error")
	}
	return io.ReadAll(response.Body)

}

func (c *Client) generateUrl(baseUrl string, queries []ccv3.Query, page int) string {
	curQueries := queries
	curQueries = append(curQueries, Large)
	if page > 0 {
		curQueries = append(curQueries, ccv3.Query{
			Key:    "page",
			Values: []string{fmt.Sprintf("%d", page)},
		})
	}

	url := baseUrl + QueriesToQueryString(curQueries)
	return url

}

func QueriesToQueryString(queries []ccv3.Query) string {
	var queryParams []string
	for key, value := range ccv3.FormatQueryParameters(queries) {
		queryParams = append(queryParams, fmt.Sprintf("%s=%s", key, value[0]))
	}
	queryString := ""
	if len(queryParams) > 0 {
		queryString = "?" + strings.Join(queryParams, "&")
	}
	return queryString

}

func (c *Client) ListAllSecGroups(req *http.Request) ([]byte, error) {
	client := &http.Client{Transport: &c.transport}
	url := c.GetApiUrl() + req.URL.RequestURI()

	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	request.Header = req.Header.Clone()
	request.Header.Set("Authorization", c.accessToken)

	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, errors.Wrap(err, "http error")
	}
	return io.ReadAll(response.Body)
}

func (c *Client) GetSecGroups(queries []ccv3.Query, page int) (SecurityGroups, error) {
	SecGroups := SecurityGroups{}
	url := c.generateUrl(c.endpoint+"/v3/security_groups", queries, page)
	buffer, err := c.doRequest(http.MethodGet, url, nil)
	if err != nil {
		return SecGroups, err
	}
	if err = json.Unmarshal(buffer, &SecGroups); err != nil {
		return SecGroups, errors.Wrap(err, "Error unmarshalling Security Groups")
	}
	if SecGroups.Pagination.Next.HREF != "" {
		NextPage, err := c.GetSecGroups(queries, page+1)
		if err != nil {
			return SecGroups, err
		}
		SecGroups.Resources = append(SecGroups.Resources, NextPage.Resources...)
	}
	return SecGroups, err
}

func (c *Client) GetSecGroupByName(name string) (SecurityGroup, error) {
	queries := []ccv3.Query{
		{
			Key:    ccv3.NameFilter,
			Values: []string{name},
		},
	}
	securityGroups, err := c.GetSecGroups(queries, 0)
	if err != nil {
		return SecurityGroup{}, err
	}
	if len(securityGroups.Resources) == 0 {
		return SecurityGroup{}, errors.New("security group " + name + " not found")
	}
	return securityGroups.Resources[0], nil
}

func (c *Client) GetSpaceByGuid(guid string) (Space, error) {
	spaces, err := c.GetSpacesWithOrg([]ccv3.Query{{Key: ccv3.GUIDFilter, Values: []string{guid}}}, 0)
	if err != nil {
		return Space{}, err
	}
	if len(spaces.Resources) == 0 {
		return Space{}, errors.New("Space " + guid + " not found")
	}
	return spaces.Resources[0], nil

}

func (c *Client) GetOrgManagers(orgGuid string, page int) (User, error) {
	user := User{}

	url := c.generateUrl(c.apiUrl+"/v3/roles", []ccv3.Query{Large, {Key: ccv3.OrganizationGUIDFilter, Values: []string{orgGuid}}}, page)
	buffer, err := c.doRequest(http.MethodGet, url, nil)

	if err = json.Unmarshal(buffer, &user); err != nil {
		return user, errors.Wrap(err, "Error unmarshalling user roles")
	}

	if user.Pagination.Next.HREF != "" {
		NextPage, err := c.GetOrgManagers(orgGuid, page+1)
		if err != nil {
			return user, err
		}
		user.Resources = append(user.Resources, NextPage.Resources...)
	}

	return user, nil
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

func (c *Client) GetSpacesWithOrg(queries []ccv3.Query, page int) (Spaces, error) {
	curQueries := queries
	curQueries = append(curQueries, ccv3.Query{Key: ccv3.Include, Values: []string{"organization"}})
	curQueries = append(curQueries, Large)
	var spaces Spaces
	url := c.generateUrl(c.apiUrl+"/v3/spaces", curQueries, page)
	buffer, err := c.doRequest(http.MethodGet, url, nil)
	if err != nil {
		return spaces, err
	}
	if err = json.Unmarshal(buffer, &spaces); err != nil {
		return spaces, errors.Wrap(err, "Error unmarshalling Spaces")
	}
	if spaces.Pagination.Next.HREF != "" {
		NextPage, err := c.GetSpacesWithOrg(queries, page+1)
		if err != nil {
			return spaces, err
		}
		spaces.Resources = append(spaces.Resources, NextPage.Resources...)
		spaces.Included.Organizations = append(spaces.Included.Organizations, NextPage.Included.Organizations...)
	}
	return spaces, nil
}

func (c *Client) GetSecGroupSpaces(secGroup *SecurityGroup) (Spaces, error) {
	var runningSpaceGuids []string
	var stagingSpaceGuids []string
	for _, data := range secGroup.Relationships.Running_Spaces.Data {
		runningSpaceGuids = append(runningSpaceGuids, data.GUID)
	}
	for _, data := range secGroup.Relationships.Staging_Spaces.Data {
		stagingSpaceGuids = append(stagingSpaceGuids, data.GUID)
	}
	spaceGuids := append(runningSpaceGuids, stagingSpaceGuids...)
	if len(spaceGuids) >= 50 {
		// chunk spacesGuids
		var spaces Spaces
		for i := 0; i < len(spaceGuids); i += 50 {
			end := i + 50
			if end > len(spaceGuids) {
				end = len(spaceGuids)
			}
			spacesChunk, err := c.GetSpacesWithOrg([]ccv3.Query{{Key: ccv3.GUIDFilter, Values: spaceGuids[i:end]}, {Key: ccv3.Include, Values: []string{"organization"}}}, 0)
			if err != nil {
				return spaces, err
			}
			spaces.Resources = append(spaces.Resources, spacesChunk.Resources...)
			spaces.Included.Organizations = append(spaces.Included.Organizations, spacesChunk.Included.Organizations...)
		}
		return spaces, nil
	}
	return c.GetSpacesWithOrg([]ccv3.Query{{Key: ccv3.GUIDFilter, Values: spaceGuids}, {Key: ccv3.Include, Values: []string{"organization"}}}, 0)
}

func (c *Client) AddSecGroupRelationShips(secGroup *SecurityGroup, spaces Spaces) error {
	for _, space := range spaces.Resources {
		var orgName string
		var orgGuid string
		for _, org := range spaces.Included.Organizations {
			if org.GUID == space.Relationships[constant.RelationshipTypeOrganization].GUID {
				orgName = org.Name
				orgGuid = org.GUID
				break
			}
		}
		for i, data := range secGroup.Relationships.Running_Spaces.Data {
			if data.GUID == space.GUID {
				secGroup.Relationships.Running_Spaces.Data[i].SpaceName = space.Name
				secGroup.Relationships.Running_Spaces.Data[i].OrgName = orgName
				secGroup.Relationships.Running_Spaces.Data[i].OrgGUID = orgGuid
			}
		}
		for i, data := range secGroup.Relationships.Staging_Spaces.Data {
			if data.GUID == space.GUID {
				secGroup.Relationships.Staging_Spaces.Data[i].SpaceName = space.Name
				secGroup.Relationships.Staging_Spaces.Data[i].OrgName = orgName
				secGroup.Relationships.Staging_Spaces.Data[i].OrgGUID = orgGuid
			}
		}
	}
	return nil
}
