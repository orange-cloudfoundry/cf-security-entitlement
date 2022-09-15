package main

import (
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/jsonry"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cloudfoundry-community/gautocloud"
	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/pkg/errors"
	"github.com/thoas/go-funk"
)

var bindReqRegex = regexp.MustCompile("^/v3/security_groups/[^/]*/relationships/(running|staging)_spaces")
var checkReqRegex = regexp.MustCompile("^/v3/security_groups/[^/]*/relationships/spaces/([^/]*)/check")
var findReqRegex = regexp.MustCompile("^/v3/security_groups(/[^/]*)?")

type SecGroupConfig struct {
	Binding *SecGroupOptions `mapstructure:"binding" json:"binding" yaml:"binding"`
}

type SecGroupOptions struct {
	Enabled bool `mapstructure:"enabled" json:"enabled" yaml:"enabled"`
}

type SecGroupMiddleware struct {
}

type body struct {
	Data []struct {
		GUID string `json:"guid"`
	}
}

func (SecGroupMiddleware) Handler(proxyRoute gobis.ProxyRoute, params interface{}, next http.Handler) (http.Handler, error) {
	config := params.(SecGroupConfig)
	options := config.Binding
	if options == nil || !options.Enabled {
		return next, nil
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if expiresAt.Before(time.Now()) {
			var config model.ConfigServer
			err := gautocloud.Inject(&config)
			if err != nil {
				return
			}
			tr := shallowDefaultTransport(config.TrustedCaCertificates, config.CloudFoundry.SkipSSLValidation)

			accessToken, refreshExpiresAt, err := AuthenticateWithExpire(config.CloudFoundry.UAAEndpoint, config.CloudFoundry.ClientID, config.CloudFoundry.ClientSecret, tr)
			if err != nil {
				errors.Wrap(err, "Error when authenticate on cf")
				return
			}
			if accessToken == "" {
				errors.Errorf("A pair of username/password or a pair of client_id/client_secret muste be set.")
				return
			}

			expiresAt = refreshExpiresAt
			cfclient.SetAccessToken(accessToken)
		}

		path := req.URL.Path
		if bindReqRegex.MatchString(path) && (req.Method == http.MethodPost || req.Method == http.MethodDelete) {
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
	_, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, http.StatusBadRequest, err)
		return
	}
	pathSplit := strings.Split(req.URL.Path, "/")
	secGroupGuid := pathSplit[3]
	spaceGuid := pathSplit[6]

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
	var dataBody body
	var spaceGuid string

	userId, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, http.StatusBadRequest, err)
		return
	}
	path := req.URL.Path
	pathSplit := strings.Split(path, "/")
	secGroupGuid := pathSplit[3]

	if req.Method == http.MethodPost {
		buf, err := ioutil.ReadAll(req.Body)
		if err != nil {
			errors.Wrap(err, "Error reading User")
			return
		}
		if err = json.Unmarshal(buf, &dataBody); err != nil {
			errors.Wrap(err, "Error unmarshaling User")
			return
		}
		if len(dataBody.Data) == 0 {
			errors.Wrap(err, "Error unmarshaling User")
		}
		spaceGuid = dataBody.Data[0].GUID
	}

	if req.Method == http.MethodDelete {
		spaceGuid = pathSplit[6]
	}

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
	if req.Method == http.MethodPost {
		if pathSplit[5] == "running_spaces" {
			err = cfclient.BindRunningSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				serverError(w, err)
				return
			}
		}
		if pathSplit[5] == "staging_spaces" {
			err = cfclient.BindStagingSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				serverError(w, err)
				return
			}
		}
	} else {
		if pathSplit[5] == "running_spaces" {
			err = cfclient.UnBindRunningSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				if strings.Contains(err.Error(), "UnprocessableEntity") {
					serverErrorCode(w, http.StatusUnprocessableEntity, fmt.Errorf("Unable to unbind security group from space with guid '%s'. Ensure the space is bound to this security group.", spaceGuid))
					return
				} else {
					serverError(w, err)
					return
				}
			}
		}
		if pathSplit[5] == "staging_spaces" {
			err = cfclient.UnBindStagingSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				if strings.Contains(err.Error(), "UnprocessableEntity") {
					serverErrorCode(w, http.StatusUnprocessableEntity, fmt.Errorf("Unable to unbind security group from space with guid '%s'. Ensure the space is bound to this security group.", spaceGuid))
					return
				} else {
					serverError(w, err)
					return
				}
			}
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
	emptyResp, _ := json.Marshal([]client.SecurityGroups{})
	userRoles, err := cfclient.GetUserManagedOrgs(userId, 0)
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

	secGroupName := filterName(req)

	var secGroups client.SecurityGroups
	var alreadyFoundedSecGroups []string
	for _, entitlement := range entitlements {
		secGroup, err := cfclient.GetSecGroupByGuid(entitlement.SecurityGroupGUID)
		alreadyFounded := false
		for _, value := range alreadyFoundedSecGroups {
			if value == secGroup.GUID {
				alreadyFounded = true
				break
			}
		}
		if alreadyFounded {
			continue
		}
		alreadyFoundedSecGroups = append(alreadyFoundedSecGroups, secGroup.GUID)
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
		users, err := cfclient.GetOrgManagers(entitlement.OrganizationGUID, 0)
		if err != nil && isNotFoundErr(err) {
			DB.Delete(&entitlement)
			return
		}
		if err != nil {
			continue
		}
		found := false
		for _, user := range users.Resources {
			if user.Relationships.User.Data.GUID == userId { // && user.Type == "organization_manager" {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		spaces, _ := GetSpaceResources(secGroup)
		finalSpaces := feedSpaces(spaces, orgIds)
		secGroup.Relationships.RunningSpaces.Data = finalSpaces
		secGroup.Relationships.StagingSpaces.Data = finalSpaces
		secGroups.Resources = append(secGroups.Resources, secGroup)
	}
	b, _ := jsonry.Marshal(secGroups)
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
		users, err := cfclient.GetOrgManagers(entitlement.OrganizationGUID, 0)
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
	spaces, _ := GetSpaceResources(secGroup)
	finalSpaces := feedSpaces(spaces, orgIds)
	secGroup.Relationships.RunningSpaces.Data = finalSpaces
	secGroup.Relationships.StagingSpaces.Data = finalSpaces
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	b, _ := json.Marshal(secGroup)
	w.Write(b)
}

func isFilterAuthorized(filter string) bool {
	authorizedFilters := []string{"names", "guids", "page", "per_page"}
	for _, v := range authorizedFilters {
		if v == filter {
			return true
		}
	}

	return false
}

func filterName(req *http.Request) string {
	return req.URL.Query().Get("names")
}

func feedSpaces(spaces []client.Space, orgIds []string) []client.Data {
	bufOrg := make(map[string]client.Organization)
	finalSpaces := make([]client.Data, 0)
	var SpaceResources client.Data
	for _, space := range spaces {
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
		SpaceResources = client.Data{
			GUID:      space.GUID,
			SpaceName: space.Name,
			OrgGUID:   org.GUID,
			OrgName:   org.Name,
		}
		finalSpaces = append(finalSpaces, SpaceResources)

	}
	return finalSpaces
}

func isUserOrgManager(userId, orgId string) (bool, error) {
	users, err := cfclient.GetOrgManagers(orgId, 0)
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

func GetSpaceResources(secGroup client.SecurityGroup) ([]client.Space, error) {
	var spacesGuid []string
	for _, space := range secGroup.Relationships.RunningSpaces.Data {
		spacesGuid = append(spacesGuid, space.GUID)
	}
	spaceResults, err := cfclient.GetSpacesWithOrg([]ccv3.Query{{Key: ccv3.GUIDFilter, Values: spacesGuid}}, 0)
	return spaceResults.Resources, err
}
