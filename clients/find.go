package clients

import (
	"encoding/json"
	"fmt"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

func (c Client) ListSecGroups() ([]cfclient.SecGroup, error) {

	secGroups := make([]cfclient.SecGroup, 0)
	endpoint := fmt.Sprintf("%s/v2/security_groups",
		c.endpoint,
	)
	for {
		req, err := http.NewRequest(http.MethodGet, endpoint, nil)
		if err != nil {
			return secGroups, err
		}
		// cfclient do check status code and set error if >= 400
		resp, err := c.cfClient.Do(req)
		if err != nil {
			return secGroups, err
		}
		defer resp.Body.Close()
		resBody, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, errors.Wrap(err, "Error reading sec group response body")
		}
		var secGroupResp cfclient.SecGroupResponse
		err = json.Unmarshal(resBody, &secGroupResp)
		if err != nil {
			return nil, errors.Wrap(err, "Error unmarshaling sec group")
		}

		for _, secGroup := range secGroupResp.Resources {
			secGroup.Entity.Guid = secGroup.Meta.Guid
			secGroup.Entity.CreatedAt = secGroup.Meta.CreatedAt
			secGroup.Entity.UpdatedAt = secGroup.Meta.UpdatedAt
			for i, space := range secGroup.Entity.SpacesData {
				space.Entity.Guid = space.Meta.Guid
				secGroup.Entity.SpacesData[i] = space
			}
			secGroups = append(secGroups, secGroup.Entity)
		}
		if secGroupResp.NextUrl == "" {
			break
		}
		endpoint = fmt.Sprintf("%s%s",
			c.endpoint,
			secGroupResp.NextUrl,
		)
	}
	return secGroups, nil
}

func (c Client) GetSecGroupByName(name string) (cfclient.SecGroup, error) {
	var secGroupResp cfclient.SecGroupResponse
	endpoint := fmt.Sprintf("%s/v2/security_groups?q=name:%s",
		c.endpoint,
		name,
	)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return cfclient.SecGroup{}, err
	}
	// cfclient do check status code and set error if >= 400
	resp, err := c.cfClient.Do(req)
	if err != nil {
		return cfclient.SecGroup{}, err
	}
	defer resp.Body.Close()
	resBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return cfclient.SecGroup{}, errors.Wrap(err, "Error reading sec group response body")
	}

	err = json.Unmarshal(resBody, &secGroupResp)
	if err != nil {
		return cfclient.SecGroup{}, errors.Wrap(err, "Error unmarshaling sec group")
	}
	if len(secGroupResp.Resources) == 0 {
		return cfclient.SecGroup{}, fmt.Errorf("No security group with name %v found", name)
	}
	secGroup := secGroupResp.Resources[0].Entity
	secGroup.Guid = secGroupResp.Resources[0].Meta.Guid
	secGroup.CreatedAt = secGroupResp.Resources[0].Meta.CreatedAt
	secGroup.UpdatedAt = secGroupResp.Resources[0].Meta.UpdatedAt
	for i, space := range secGroupResp.Resources[0].Entity.SpacesData {
		space.Entity.Guid = space.Meta.Guid
		secGroupResp.Resources[0].Entity.SpacesData[i] = space
	}
	return secGroup, nil
}

func (c Client) GetSecGroupByGuid(guid string) (*cfclient.SecGroup, error) {
	endpoint := fmt.Sprintf("%s/v2/security_groups/%s",
		c.endpoint,
		guid,
	)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	// cfclient do check status code and set error if >= 400
	resp, err := c.cfClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	bodyRaw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "Could not read response body")
	}
	jStruct := cfclient.SecGroupResource{}
	// make it a SecGroup
	err = json.Unmarshal(bodyRaw, &jStruct)
	if err != nil {
		return nil, errors.Wrap(err, "Could not unmarshal response body as json")
	}
	// pull a few extra fields from other places
	ret := jStruct.Entity
	ret.Guid = jStruct.Meta.Guid
	ret.CreatedAt = jStruct.Meta.CreatedAt
	ret.UpdatedAt = jStruct.Meta.UpdatedAt
	for i, space := range jStruct.Entity.SpacesData {
		space.Entity.Guid = space.Meta.Guid
		jStruct.Entity.SpacesData[i] = space
	}
	return &ret, nil
}

func (c Client) GetSecGroupSpaces(guid string) ([]cfclient.Space, error) {
	spaces := make([]cfclient.Space, 0)

	secgroup, err := c.GetSecGroupByGuid(guid)
	if err != nil {
		return spaces, err
	}

	for _, space := range secgroup.SpacesData {
		space.Entity.Guid = space.Meta.Guid
		space.Entity.CreatedAt = space.Meta.CreatedAt
		space.Entity.UpdatedAt = space.Meta.UpdatedAt
		spaces = append(spaces, space.Entity)
	}

	return spaces, nil
}
