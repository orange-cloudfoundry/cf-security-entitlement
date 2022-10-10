package client

import (
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3/constant"
	"code.cloudfoundry.org/cli/resources"
	"encoding/json"
	"fmt"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
)

type Spaces struct {
	Paginated
	Resources []Space                `jsonry:"resources"`
	Included  ccv3.IncludedResources `jsonry:"included"`
}

type Space struct {
	resources.Space
}

type Data struct {
	GUID      string `jsonry:"guid,omitempty"`
	SpaceName string `jsonry:"spacename,omitempty"`
	OrgGUID   string `jsonry:"orgguid,omitempty"`
	OrgName   string `jsonry:"orgname,omitempty"`
}

type Entitlements struct {
	Resources []model.EntitlementSecGroup `jsonry:"resources"`
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

var large = ccv3.Query{
	Key:    ccv3.PerPage,
	Values: []string{"5000"},
}

var orderByTimestampDesc = ccv3.Query{
	Key:    ccv3.OrderBy,
	Values: []string{"-created_at"},
}

func (s *SecurityGroup) FeedOrgsAndSpace(spaces []Space, orgs []resources.Organization, orgGUID string) {
	stagingRelationShips := make([]Data, 0)
	runningRelationShips := make([]Data, 0)
	for _, org := range orgs {
		if org.GUID == orgGUID {
			for _, space := range spaces {
				if space.Relationships[constant.RelationshipTypeOrganization].GUID == orgGUID {
					for _, data := range s.Relationships.Staging_Spaces.Data {
						if data.GUID == space.GUID {
							stagingRelationShips = append(stagingRelationShips, Data{
								GUID:      space.GUID,
								SpaceName: space.Name,
								OrgGUID:   orgGUID,
								OrgName:   org.Name,
							})
						}
					}
					for _, data := range s.Relationships.Running_Spaces.Data {
						if data.GUID == space.GUID {
							runningRelationShips = append(runningRelationShips, Data{
								GUID:      space.GUID,
								SpaceName: space.Name,
								OrgGUID:   orgGUID,
								OrgName:   org.Name,
							})
						}
					}
				}
			}
		}
		if len(stagingRelationShips) <= 0 {
			stagingRelationShips = append(stagingRelationShips, Data{
				OrgGUID: orgGUID,
				OrgName: org.Name,
			})
		}
		if len(runningRelationShips) <= 0 {
			runningRelationShips = append(runningRelationShips, Data{
				OrgGUID: orgGUID,
				OrgName: org.Name,
			})
		}
	}
	s.Relationships.Staging_Spaces.Data = stagingRelationShips
	s.Relationships.Running_Spaces.Data = runningRelationShips
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
	return ioutil.ReadAll(response.Body)

}

func (c *Client) generateUrl(baseUrl string, queries []ccv3.Query, page int) string {
	curQueries := queries
	curQueries = append(curQueries, large)
	if page > 0 {
		curQueries = append(curQueries, ccv3.Query{
			Key:    "page",
			Values: []string{fmt.Sprintf("%d", page)},
		})
	}

	// Build queryString
	var queryParams []string
	for key, value := range ccv3.FormatQueryParameters(curQueries) {
		queryParams = append(queryParams, fmt.Sprintf("%s=%s", key, value[0]))
	}
	queryString := ""
	if len(queryParams) > 0 {
		queryString = "?" + strings.Join(queryParams, "&")
	}
	url := baseUrl + queryString
	return url

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

func (c *Client) GetSecGroupByGuid(guid string) (SecurityGroup, error) {
	queries := []ccv3.Query{
		{Key: ccv3.GUIDFilter, Values: []string{guid}},
	}
	securityGroups, err := c.GetSecGroups(queries, 0)
	if err != nil {
		return SecurityGroup{}, err
	}
	if len(securityGroups.Resources) == 0 {
		return SecurityGroup{}, errors.New("security group " + guid + " not found")
	}
	return securityGroups.Resources[0], nil
}

func (c *Client) GetOrgByGuid(guid string) (Organization, error) {
	var orgs []Organization
	_, _, err := c.ccv3Client.MakeListRequest(ccv3.RequestParams{
		RequestName:  "GetOrganizations",
		Query:        []ccv3.Query{{Key: ccv3.GUIDFilter, Values: []string{guid}}, {Key: ccv3.PerPage, Values: []string{"1"}}},
		ResponseBody: Organization{},
		AppendToList: func(item interface{}) error {
			orgs = append(orgs, item.(Organization))
			return nil
		},
	})
	if err != nil {
		return Organization{}, err
	}
	if len(orgs) == 0 {
		return Organization{}, errors.New("Organization " + guid + " not found")
	}
	return orgs[0], nil
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

func (c *Client) GetUserManagedSpacesAndOrgs(userGUID string) ([]Space, []resources.Organization, error) {
	var spacesResult Spaces
	roles, err := c.GetRoles(
		[]ccv3.Query{
			{Key: ccv3.UserGUIDFilter, Values: []string{userGUID}},
			{Key: ccv3.RoleTypesFilter, Values: []string{string(constant.OrgManagerRole)}},
		},
		0)
	if err != nil {
		return nil, nil, errors.Wrap(err, "Error getting managed spaces")
	}
	orgIds := make([]string, len(roles.Resources))
	for _, role := range roles.Resources {
		if role.Relationships.Organization.Data.GUID != "" {
			orgIds = append(orgIds, role.Relationships.Organization.Data.GUID)
		}
	}
	spacesResult, err = c.GetSpacesWithOrg(
		[]ccv3.Query{{Key: ccv3.OrganizationGUIDFilter, Values: orgIds}},
		0,
	)
	if err != nil {
		return nil, nil, errors.Wrap(err, fmt.Sprintf("Error getting managed spaces for user %s", userGUID))
	}
	orgsResult, err := c.GetOrganizations(
		[]ccv3.Query{{Key: ccv3.GUIDFilter, Values: orgIds}},
		0,
	)
	for _, org := range orgsResult.Resources {
		spacesResult.Included.Organizations = append(spacesResult.Included.Organizations, org.Organization)
	}
	return spacesResult.Resources, spacesResult.Included.Organizations, nil
}

func (c *Client) GetRoles(queries []ccv3.Query, page int) (UserRoles, error) {
	var rolesResult UserRoles
	url := c.generateUrl(c.apiUrl+"/v3/roles", queries, page)
	buffer, err := c.doRequest(http.MethodGet, url, nil)
	if err != nil {
		return rolesResult, errors.Wrap(err, "Error getting roles")
	}
	if err = json.Unmarshal(buffer, &rolesResult); err != nil {
		return rolesResult, errors.Wrap(err, "Error unmarshalling Roles")
	}
	if rolesResult.Pagination.Next.HREF != "" {
		NextPage, err := c.GetRoles(queries, page+1)
		if err != nil {
			return rolesResult, err
		}
		rolesResult.Resources = append(rolesResult.Resources, NextPage.Resources...)
	}
	return rolesResult, err
}

func (c *Client) GetOrgManagedUserRoles(userGuid string, page int) (UserRoles, error) {
	var userRoles UserRoles

	url := c.generateUrl(c.apiUrl+"/v3/roles", []ccv3.Query{large, {Key: ccv3.UserGUIDFilter, Values: []string{userGuid}}}, 0)
	buffer, err := c.doRequest(http.MethodGet, url, nil)
	if err != nil {
		return userRoles, err
	}
	if err = json.Unmarshal(buffer, &userRoles); err != nil {
		return userRoles, errors.Wrap(err, "Error unmarshalling User roles")
	}
	if userRoles.Pagination.Next.HREF != "" {
		NextPage, err := c.GetOrgManagedUserRoles(userGuid, page+1)
		if err != nil {
			return userRoles, err
		}
		userRoles.Resources = append(userRoles.Resources, NextPage.Resources...)
	}
	return userRoles, nil
}

func (c *Client) GetOrgManagers(orgGuid string, page int) (User, error) {
	user := User{}

	url := c.generateUrl(c.apiUrl+"/v3/roles", []ccv3.Query{large, {Key: ccv3.OrganizationGUIDFilter, Values: []string{orgGuid}}}, page)
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

func (c *Client) GetTransport() http.Transport {
	return c.transport
}

func (c *Client) GetSpacesWithOrg(queries []ccv3.Query, page int) (Spaces, error) {
	curQueries := queries
	curQueries = append(curQueries, ccv3.Query{Key: ccv3.Include, Values: []string{"organization"}})
	curQueries = append(curQueries, large)
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

func (c *Client) GetSpaces(queries []ccv3.Query, page int) (Spaces, error) {
	curQueries := queries
	curQueries = append(curQueries, large)
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
		NextPage, err := c.GetSpaces(queries, page+1)
		if err != nil {
			return spaces, err
		}
		spaces.Resources = append(spaces.Resources, NextPage.Resources...)
	}
	return spaces, nil
}

func (c *Client) GetOrganizations(queries []ccv3.Query, page int) (Organizations, error) {
	curQueries := queries
	curQueries = append(curQueries, large)
	var orgs Organizations
	url := c.generateUrl(c.apiUrl+"/v3/organizations", curQueries, page)
	buffer, err := c.doRequest(http.MethodGet, url, nil)
	if err != nil {
		return orgs, err
	}
	if err = json.Unmarshal(buffer, &orgs); err != nil {
		return orgs, errors.Wrap(err, "Error unmarshalling Organizations")
	}
	if orgs.Pagination.Next.HREF != "" {
		NextPage, err := c.GetOrganizations(queries, page+1)
		if err != nil {
			return orgs, err
		}
		orgs.Resources = append(orgs.Resources, NextPage.Resources...)
	}
	return orgs, nil
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
	spaces, err := c.GetSpacesWithOrg([]ccv3.Query{{Key: ccv3.GUIDFilter, Values: append(runningSpaceGuids, stagingSpaceGuids...)}, {Key: ccv3.Include, Values: []string{"organization"}}}, 0)
	return spaces, err
}

func (c *Client) AddSecGroupRelationShips(secGroup *SecurityGroup) error {
	spaces, err := c.GetSecGroupSpaces(secGroup)
	if err != nil {
		return err
	}
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
