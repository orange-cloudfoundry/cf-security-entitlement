package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
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

type finalSpaces struct {
	Organization  client.Organization
	Space         client.Space
	SecurityGroup client.SecurityGroup
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

	space, err := cfclient.GetSpaceByGuid(spaceGuid)
	if err != nil {
		serverError(w, err)
		return
	}
	var entitlement model.EntitlementSecGroup
	DB.Where(&model.EntitlementSecGroup{
		OrganizationGUID:  space.Relationships["organization"].GUID,
		SecurityGroupGUID: secGroupGuid,
	}).First(&entitlement)

	data := struct {
		OrganizationGUID string `json:"organization_guid"`
		IsEntitled       bool   `json:"is_entitled"`
	}{
		OrganizationGUID: space.Relationships["organization"].GUID,
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

	space, err := cfclient.GetSpaceByGuid(spaceGuid)
	if err != nil {
		serverError(w, err)
		return
	}
	var entitlement model.EntitlementSecGroup
	DB.Where(&model.EntitlementSecGroup{
		OrganizationGUID:  space.Relationships["organization"].GUID,
		SecurityGroupGUID: secGroupGuid,
	}).First(&entitlement)
	if entitlement.OrganizationGUID == "" {
		serverErrorCode(w, http.StatusUnauthorized, fmt.Errorf(
			"Org %s not entitled with security group %s for space %s",
			space.Relationships["organization"].GUID,
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
		err = cfclient.BindSecurityGroup(secGroupGuid, spaceGuid)
		if err != nil {
			serverError(w, err)
			return
		}
		err = cfclient.BindStagingSecGroupToSpace(secGroupGuid, spaceGuid)
		if err != nil {
			serverError(w, err)
			return
		}
	} else {
		err = cfclient.UnbindSecurityGroup(secGroupGuid, spaceGuid)
		if err != nil {
			serverError(w, err)
			return
		}
		err = cfclient.UnbindStagingSecGroupToSpace(secGroupGuid, spaceGuid)
		if err != nil {
			serverError(w, err)
			return
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
	emptyResp, _ := json.Marshal([]client.SecurityGroup{})
	userRoles, err := cfclient.ListUserManagedOrgs(userId)
	if err != nil {
		serverError(w, err)
		return
	}
	if len(userRoles.Resources) == 0 {
		w.Write(emptyResp)
		return
	}

	orgIds := make([]string, len(userRoles.Resources))
	i := 0
	for _, org := range userRoles.Resources {
		if org.Type == "organization_manager" {
			orgIds[i] = org.Relationships.Organization.Data.GUID
			i++
		}
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

	secGroups := make([]finalSpaces, 0)
	for i, entitlement := range entitlements {
		users, err := cfclient.ListOrgManagers(entitlement.OrganizationGUID)
		if err != nil && isNotFoundErr(err) {
			DB.Delete(&entitlement)
			return
		}
		if err != nil {
			continue
		}
		found := false
		for _, user := range users.Resources {
			if user.Relationships.User.Data.GUID == userId && user.Type == "organization_manager" {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		secGroup, err := cfclient.GetSecGroupByGuid(entitlement.SecurityGroupGUID)
		if err != nil && isNotFoundErr(err) {
			DB.Delete(&entitlement)
			return
		}
		if err != nil {
			continue
		}
		if secGroupName != "" && secGroup.Resources[0].Name != secGroupName {
			continue
		}
		// attention ??
		var finalSecGroup []finalSpaces
		spaces, _ := ListSpaceResources(secGroup)
		finalOrgSpaces := feedSpaces(spaces, orgIds)
		secGroups[i].Space = finalOrgSpaces[i].Space
		secGroups[i].SecurityGroup = secGroup
		finalSecGroup[i] = secGroups[i]
	}
	// ça marche comme ça ?
	b, _ := json.Marshal(finalSpaces{})
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
		users, err := cfclient.ListOrgManagers(entitlement.OrganizationGUID)
		if err != nil && isNotFoundErr(err) {
			DB.Delete(&entitlement)
			return
		}
		if err != nil {
			continue
		}
		for _, user := range users.Resources {
			if user.Relationships.User.Data.GUID == userId {
				found = true
				orgIds = append(orgIds, entitlement.OrganizationGUID)
			}
		}
	}
	if !found {
		serverErrorCode(w, http.StatusNotFound, fmt.Errorf("Security %s not found", secGroupGuid))
		return
	}
	secGroup, err := cfclient.GetSecGroupByGuid(secGroupGuid)
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
	// attention aussi
	spaces, _ := ListSpaceResources(secGroup)
	finalOrgSpaces := feedSpaces(spaces, orgIds)
	finalOrgSpaces[0].SecurityGroup = secGroup
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	b, _ := json.Marshal(finalSpaces{
		Organization:  finalOrgSpaces[0].Organization,
		Space:         finalOrgSpaces[0].Space,
		SecurityGroup: finalOrgSpaces[0].SecurityGroup,
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

func feedSpaces(spaces []client.Space, orgIds []string) []finalSpaces {
	bufOrg := make(map[string]client.Organization)
	finalSpaces := make([]finalSpaces, 0)
	for i, space := range spaces {
		if !funk.ContainsString(orgIds, space.Relationships["organization"].GUID) {
			continue
		}
		var org client.Organization
		if tmpOrg, ok := bufOrg[space.Relationships["organization"].GUID]; ok && tmpOrg.GUID != "" {
			org = tmpOrg
		} else {
			org, _ = cfclient.GetOrgByGuid(space.Relationships["organization"].GUID)
			bufOrg[org.GUID] = org
		}

		finalSpaces[i].Organization = org
		finalSpaces[i].Space = space
	}
	return finalSpaces
}

func isUserOrgManager(userId, orgId string) (bool, error) {
	users, err := cfclient.ListOrgManagers(orgId)
	if err != nil {
		return false, err
	}
	found := false
	for _, user := range users.Resources {
		if user.Relationships.User.Data.GUID == userId && user.Type == "organization_manager" {
			found = true
			break
		}
	}
	return found, nil
}

func ListSpaceResources(secGroup client.SecurityGroup) ([]client.Space, error) {
	var spaces []client.Space
	for i, spaceGuid := range secGroup.Resources[0].Relationships.Running_spaces.Data {
		space, err := cfclient.GetSpaceByGuid(spaceGuid.GUID)
		if err != nil {
			return spaces, err
		}
		spaces[i] = space
	}
	return spaces, nil
}
