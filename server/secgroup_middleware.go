package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/thoas/go-funk"
)

var bindReqRegex = regexp.MustCompile("^/v2/security_groups/[^/]*/spaces/[^/]*")
var checkReqRegex = regexp.MustCompile("^/v2/security_groups/[^/]*/spaces/[^/]*/check")
var findReqRegex = regexp.MustCompile("^/v2/security_groups(/[^/]*)?")

type SecGroupConfig struct {
	Binding *SecGroupOptions `mapstructure:"binding" json:"binding" yaml:"binding"`
}

type SecGroupOptions struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type SecGroupMiddleware struct {
}

func (SecGroupMiddleware) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(SecGroupConfig)
	options := config.Binding
	if options == nil || !options.Enabled {
		return next, nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path
		if bindReqRegex.MatchString(path) && (req.Method == http.MethodPut || req.Method == http.MethodDelete) {
			bindOrUnbindSecGroup(w, req, next)
			return
		}
		if checkReqRegex.MatchString(path) && req.Method == http.MethodGet {
			checkBind(w, req, next)
			return
		}
		if findReqRegex.MatchString(path) && req.Method == http.MethodGet {
			findSecGroup(w, req, next)
			return
		}

		gobis.UndirtHeader(req, "Authorization")
		next.ServeHTTP(w, req)

	}), nil
}

func (SecGroupMiddleware) Schema() interface{} {
	return SecGroupConfig{}
}

func checkBind(w http.ResponseWriter, req *http.Request, next http.Handler) {
	path := strings.TrimSuffix(req.URL.Path, "/check")
	_, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, http.StatusBadRequest, err)
		return
	}
	pathSplit := strings.Split(path, "/")
	secGroupGuid := pathSplit[3]
	spaceGuid := pathSplit[5]

	space, err := client.GetSpaceByGuid(spaceGuid)
	if err != nil {
		serverError(w, err)
		return
	}
	var entitlement model.EntitlementSecGroup
	DB.Where(&model.EntitlementSecGroup{
		OrganizationGUID:  space.OrganizationGuid,
		SecurityGroupGUID: secGroupGuid,
	}).First(&entitlement)

	data := struct {
		OrganizationGUID string `json:"organization_guid"`
		IsEntitled       bool   `json:"is_entitled"`
	}{
		OrganizationGUID: space.OrganizationGuid,
		IsEntitled:       entitlement.OrganizationGUID != "",
	}
	b, _ := json.MarshalIndent(data, "", "  ")
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(b)
}

func bindOrUnbindSecGroup(w http.ResponseWriter, req *http.Request, next http.Handler) {
	path := req.URL.Path
	userId, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, http.StatusBadRequest, err)
		return
	}
	pathSplit := strings.Split(path, "/")
	secGroupGuid := pathSplit[3]
	spaceGuid := pathSplit[5]

	space, err := client.GetSpaceByGuid(spaceGuid)
	if err != nil {
		serverError(w, err)
		return
	}
	var entitlement model.EntitlementSecGroup
	DB.Where(&model.EntitlementSecGroup{
		OrganizationGUID:  space.OrganizationGuid,
		SecurityGroupGUID: secGroupGuid,
	}).First(&entitlement)
	if entitlement.OrganizationGUID == "" {
		serverErrorCode(w, http.StatusUnauthorized, fmt.Errorf(
			"Org %s not entitled with security group %s for space %s",
			space.OrganizationGuid,
			secGroupGuid,
			spaceGuid,
		))
		return
	}
	if !isAdmin(gobis.Groups(req)) {
		hasAccess, err := isUserOrgManager(userId, entitlement.OrganizationGUID)
		if err != nil {
			serverError(w, err)
			return
		}
		if !hasAccess {
			serverErrorCode(w, http.StatusUnauthorized, fmt.Errorf(""))
			return
		}
	}
	if req.Method == http.MethodPut {
		err = client.BindSecGroup(secGroupGuid, spaceGuid)
		if err != nil {
			serverError(w, err)
			return
		}
		err = client.BindStagingSecGroupToSpace(secGroupGuid, spaceGuid)
		if err != nil {
			serverError(w, err)
			return
		}
	} else {
		err = client.UnbindSecGroup(secGroupGuid, spaceGuid)
		if err != nil {
			serverError(w, err)
			return
		}
		resp, err := client.DoRequest(client.NewRequest("DELETE",
			fmt.Sprintf("/v2/security_groups/%s/staging_spaces/%s", secGroupGuid, spaceGuid)),
		)
		if err != nil {
			serverError(w, err)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 201 {
			serverErrorCode(w, resp.StatusCode, fmt.Errorf(""))
		}
	}

}

func findSecGroup(w http.ResponseWriter, req *http.Request, next http.Handler) {
	path := req.URL.Path
	userId, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, http.StatusBadRequest, err)
		return
	}
	if isAdmin(gobis.Groups(req)) {
		gobis.UndirtHeader(req, "Authorization")
		next.ServeHTTP(w, req)
		return
	}
	pathSplit := strings.Split(path, "/")
	if len(pathSplit) == 4 && pathSplit[3] != "" {
		retrieveSecGroup(w, req, pathSplit[3], userId)
		return
	}
	retrieveSecGroups(w, req, userId)
}

func retrieveSecGroups(w http.ResponseWriter, req *http.Request, userId string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	emptyResp, _ := json.Marshal(cfclient.SecGroupResponse{
		Pages:     1,
		Resources: []cfclient.SecGroupResource{},
	})
	orgs, err := client.ListUserManagedOrgs(userId)
	if err != nil {
		serverError(w, err)
		return
	}
	if len(orgs) == 0 {
		w.Write(emptyResp)
		return
	}

	orgIds := make([]string, len(orgs))
	for i, org := range orgs {
		orgIds[i] = org.Guid
	}

	entitlements := make([]model.EntitlementSecGroup, 0)
	DB.Where("organization_guid in (?)", orgIds).Find(&entitlements)
	if len(entitlements) == 0 {
		w.Write(emptyResp)
		return
	}

	secGroupName, err := filterName(req)
	if err != nil {
		serverErrorCode(w, http.StatusBadRequest, err)
		return
	}

	secGroups := make([]cfclient.SecGroupResource, 0)
	for _, entitlement := range entitlements {
		users, err := client.ListOrgManagers(entitlement.OrganizationGUID)
		if err != nil && isNotFoundErr(err) {
			DB.Delete(&entitlement)
			return
		}
		if err != nil {
			continue
		}
		found := false
		for _, user := range users {
			if user.Guid == userId {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		secGroup, err := client.GetSecGroup(entitlement.SecurityGroupGUID)
		if err != nil && isNotFoundErr(err) {
			DB.Delete(&entitlement)
			return
		}
		if err != nil {
			continue
		}
		if secGroupName != "" && secGroup.Name != secGroupName {
			continue
		}
		spaces, _ := secGroup.ListSpaceResources()
		finalSpaces := feedSpaces(spaces, orgIds)
		secGroup.SpacesData = finalSpaces
		secGroups = append(secGroups, cfclient.SecGroupResource{
			Meta: cfclient.Meta{
				Guid:      secGroup.Guid,
				CreatedAt: secGroup.CreatedAt,
				UpdatedAt: secGroup.UpdatedAt,
			},
			Entity: *secGroup,
		})
	}
	b, _ := json.Marshal(cfclient.SecGroupResponse{
		Count:     len(secGroups),
		Pages:     1,
		Resources: secGroups,
	})
	w.Write(b)
}

func retrieveSecGroup(w http.ResponseWriter, req *http.Request, secGroupGuid, userId string) {
	entitlements := make([]model.EntitlementSecGroup, 0)
	DB.Where(&model.EntitlementSecGroup{
		SecurityGroupGUID: secGroupGuid,
	}).Find(&entitlements)
	if len(entitlements) == 0 {
		serverErrorCode(w, http.StatusNotFound, fmt.Errorf("Security group not found"))
		return
	}
	orgIds := make([]string, 0)
	found := false
	for _, entitlement := range entitlements {
		users, err := client.ListOrgManagers(entitlement.OrganizationGUID)
		if err != nil && isNotFoundErr(err) {
			DB.Delete(&entitlement)
			return
		}
		if err != nil {
			continue
		}
		for _, user := range users {
			if user.Guid == userId {
				found = true
				orgIds = append(orgIds, entitlement.OrganizationGUID)
			}
		}
	}
	if !found {
		serverErrorCode(w, http.StatusNotFound, fmt.Errorf("Security %s not found", secGroupGuid))
		return
	}
	secGroup, err := client.GetSecGroup(secGroupGuid)
	if err != nil && isNotFoundErr(err) {
		DB.Where(&model.EntitlementSecGroup{
			SecurityGroupGUID: secGroupGuid,
		}).Delete(model.EntitlementSecGroup{})
		return
	}
	if err != nil {
		serverError(w, err)
		return
	}
	spaces, _ := secGroup.ListSpaceResources()
	finalSpaces := feedSpaces(spaces, orgIds)
	secGroup.SpacesData = finalSpaces
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	b, _ := json.Marshal(cfclient.SecGroupResource{
		Meta: cfclient.Meta{
			Guid:      secGroup.Guid,
			CreatedAt: secGroup.CreatedAt,
			UpdatedAt: secGroup.UpdatedAt,
		},
		Entity: *secGroup,
	})
	w.Write(b)
}

func filterName(req *http.Request) (string, error) {
	q, ok := req.URL.Query()["q"]
	if !ok {
		return "", nil
	}

	qSplit := strings.SplitN(q[0], ":", 2)
	if qSplit[0] != "name" || len(qSplit) != 2 {
		return "", fmt.Errorf("Invalid filter")
	}
	return qSplit[1], nil
}

func feedSpaces(spaces []cfclient.SpaceResource, orgIds []string) []cfclient.SpaceResource {
	bufOrg := make(map[string]cfclient.Org)
	finalSpaces := make([]cfclient.SpaceResource, 0)
	for _, space := range spaces {
		if !funk.ContainsString(orgIds, space.Entity.OrganizationGuid) {
			continue
		}
		var org cfclient.Org
		if tmpOrg, ok := bufOrg[space.Entity.OrganizationGuid]; ok && tmpOrg.Guid != "" {
			org = tmpOrg
		} else {
			org, _ = client.GetOrgByGuid(space.Entity.OrganizationGuid)
			bufOrg[org.Guid] = org
		}
		space.Entity.OrgData = cfclient.OrgResource{
			Meta: cfclient.Meta{
				Guid:      org.Guid,
				UpdatedAt: org.UpdatedAt,
				CreatedAt: org.CreatedAt,
			},
			Entity: org,
		}
		finalSpaces = append(finalSpaces, space)
	}
	return finalSpaces
}

func isUserOrgManager(userId, orgId string) (bool, error) {
	users, err := client.ListOrgManagers(orgId)
	if err != nil {
		return false, err
	}
	found := false
	for _, user := range users {
		if user.Guid == userId {
			found = true
			break
		}
	}
	return found, nil
}
