package main

import (
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3/constant"
	"code.cloudfoundry.org/cli/resources"
	"code.cloudfoundry.org/jsonry"
	"encoding/json"
	"fmt"
	"io"
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
		buf, err := io.ReadAll(req.Body)
		if err != nil {
			errors.Wrap(errors.Wrap(err, "Error reading body"), "Error binding security group")
			return
		}
		if err = json.Unmarshal(buf, &dataBody); err != nil {
			errors.Wrap(errors.Wrap(err, "Error unmarshalling body"), "Error binding security group")
			return
		}
		if len(dataBody.Data) == 0 {
			errors.Wrap(errors.Wrap(err, "Error no data in body"), "Error binding security group")
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
	guid := filterGuid(req)
	if guid != "" {
		retrieveSecGroup(w, req, guid, userId)
		return
	}
	retrieveSecGroups(w, req, userId)
}

func retrieveSecGroups(w http.ResponseWriter, req *http.Request, userId string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := client.SecurityGroups{}
	spaces, orgs, err := cfclient.GetUserManagedSpacesAndOrgs(userId)
	if err != nil {
		serverError(w, err)
		return
	}
	orgIds := make([]string, len(orgs))
	for _, org := range orgs {
		orgIds = append(orgIds, org.GUID)
	}

	entitlements := make([]model.EntitlementSecGroup, 0)
	DB.Where("organization_guid in (?)", orgIds).Find(&entitlements)
	entitledOrgIds := make([]string, len(entitlements))
	entitledSecGroupIds := make([]string, len(entitlements))
	for _, entitlement := range entitlements {
		entitledOrgIds = append(entitledOrgIds, entitlement.OrganizationGUID)
		entitledSecGroupIds = append(entitledSecGroupIds, entitlement.SecurityGroupGUID)
	}

	secGroupsResult := client.SecurityGroups{Resources: make([]client.SecurityGroup, 0)}

	chunkEntitledSecGroupIds := ChunkSlice(entitledSecGroupIds, 20)
	for _, chunk := range chunkEntitledSecGroupIds {
		queries := make([]ccv3.Query, 0)
		queries = append(queries, ccv3.Query{Key: ccv3.GUIDFilter, Values: chunk})
		names := filterNames(req)
		if len(names) > 0 {
			queries = append(queries, ccv3.Query{Key: ccv3.NameFilter, Values: names})
		}
		cSecGroupsResult, err := cfclient.GetSecGroups(queries, 0)
		if err == nil {
			secGroupsResult.Resources = append(secGroupsResult.Resources, cSecGroupsResult.Resources...)
		}
	}

	DeleteInconsistantEntitlements(entitlements)

	if len(secGroupsResult.Resources) == 0 {
		serverErrorCode(w, http.StatusNotFound, fmt.Errorf("No security groups found"))
		return
	}

	response.Resources = FeedSecGroups(secGroupsResult.Resources, entitlements, spaces, orgs)

	b, _ := jsonry.Marshal(response)
	_, _ = w.Write(b)

}

func retrieveSecGroup(w http.ResponseWriter, req *http.Request, secGroupGuid, userId string) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	response := client.SecurityGroups{}

	spaces, orgs, err := cfclient.GetUserManagedSpacesAndOrgs(userId)
	if err != nil {
		serverError(w, err)
		return
	}
	orgIds := make([]string, len(orgs))
	for _, org := range orgs {
		orgIds = append(orgIds, org.GUID)
	}

	entitlements := make([]model.EntitlementSecGroup, 0)
	DB.Where(&model.EntitlementSecGroup{
		SecurityGroupGUID: secGroupGuid,
	}).Find(&entitlements)
	if len(entitlements) == 0 {
		serverErrorCode(w, http.StatusNotFound, fmt.Errorf("No security group found with guid '%s'", secGroupGuid))
		return
	}

	secGroup, err := cfclient.GetSecGroupByGuid(secGroupGuid)
	if err != nil {
		serverError(w, err)
		return
	}

	DeleteInconsistantEntitlements(entitlements)

	response.Resources = FeedSecGroups([]client.SecurityGroup{secGroup}, entitlements, spaces, orgs)
	if len(response.Resources) == 0 {
		serverErrorCode(w, http.StatusNotFound, fmt.Errorf("No security group found with guid '%s'", secGroupGuid))
		return
	}

	b, _ := json.Marshal(response.Resources[0])
	w.Write(b)
}

func ChunkSlice(slice []string, chunkSize int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += chunkSize {
		end := i + chunkSize
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

func FeedSecGroups(secGroups []client.SecurityGroup, entitlements []model.EntitlementSecGroup, spaces []client.Space, orgs []resources.Organization) []client.SecurityGroup {
	secGroupOrgIds := make(map[string][]string, 0)
	for _, entitlements := range entitlements {
		if _, ok := secGroupOrgIds[entitlements.SecurityGroupGUID]; !ok {
			secGroupOrgIds[entitlements.SecurityGroupGUID] = make([]string, 0)
		}
		secGroupOrgIds[entitlements.SecurityGroupGUID] = append(secGroupOrgIds[entitlements.SecurityGroupGUID], entitlements.OrganizationGUID)
	}

	for i, secGroup := range secGroups {
		runningSpaces := make([]client.Data, 0)
		stagingSpaces := make([]client.Data, 0)
		alreadyFoundOrgs := make([]string, 0)
		if orgIds, ok := secGroupOrgIds[secGroup.GUID]; ok {
			for _, orgId := range orgIds {
				for _, org := range orgs {
					if org.GUID == orgId {
						if funk.ContainsString(alreadyFoundOrgs, org.GUID) {
							continue
						}
						alreadyFoundOrgs = append(alreadyFoundOrgs, org.GUID)
						orgRunningSpaces := make([]client.Data, 0)
						orgStagingSpaces := make([]client.Data, 0)
						alreadyFoundStaging := make([]string, 0)
						alreadyFoundRunning := make([]string, 0)
						for _, space := range spaces {
							if space.Relationships[constant.RelationshipTypeOrganization].GUID == orgId {
								for _, data := range secGroup.Relationships.Staging_Spaces.Data {
									if data.GUID == space.GUID {
										if !funk.ContainsString(alreadyFoundStaging, space.GUID) {
											orgStagingSpaces = append(orgStagingSpaces, client.Data{
												GUID:      space.GUID,
												SpaceName: space.Name,
												OrgName:   org.Name,
												OrgGUID:   org.GUID,
											})
											alreadyFoundStaging = append(alreadyFoundStaging, space.GUID)
										}
									}
								}
								for _, data := range secGroup.Relationships.Running_Spaces.Data {
									if data.GUID == space.GUID {
										if !funk.ContainsString(alreadyFoundRunning, space.GUID) {
											orgRunningSpaces = append(orgRunningSpaces, client.Data{
												GUID:      space.GUID,
												SpaceName: space.Name,
												OrgName:   org.Name,
												OrgGUID:   org.GUID,
											})
											alreadyFoundRunning = append(alreadyFoundRunning, space.GUID)
										}
									}
								}
							}
						}
						if len(orgStagingSpaces) <= 0 {
							orgStagingSpaces = append(orgStagingSpaces, client.Data{
								GUID:      "",
								SpaceName: "",
								OrgName:   org.Name,
								OrgGUID:   org.GUID,
							})
						}
						if len(orgRunningSpaces) <= 0 {
							orgRunningSpaces = append(orgRunningSpaces, client.Data{
								GUID:      "",
								SpaceName: "",
								OrgName:   org.Name,
								OrgGUID:   org.GUID,
							})
						}
						stagingSpaces = append(stagingSpaces, orgStagingSpaces...)
						runningSpaces = append(runningSpaces, orgRunningSpaces...)
					}
				}
			}
		}
		secGroups[i].Relationships.Staging_Spaces.Data = stagingSpaces
		secGroups[i].Relationships.Running_Spaces.Data = runningSpaces
	}

	return secGroups
}

func DeleteInconsistantEntitlements(entitlements []model.EntitlementSecGroup) {

	entitledSecGroupGUIDs := make([]string, 0)
	for _, entitlement := range entitlements {
		entitledSecGroupGUIDs = append(entitledSecGroupGUIDs, entitlement.SecurityGroupGUID)
	}

	existingSecGroups := client.SecurityGroups{Resources: make([]client.SecurityGroup, 0)}
	chunkedEntitledSecGroupGUIDs := ChunkSlice(entitledSecGroupGUIDs, 20)
	for _, chunk := range chunkedEntitledSecGroupGUIDs {
		cExistingSecGroups, err := cfclient.GetSecGroups([]ccv3.Query{{Key: ccv3.GUIDFilter, Values: chunk}}, 0)
		if err != nil {
			return
		}
		existingSecGroups.Resources = append(existingSecGroups.Resources, cExistingSecGroups.Resources...)
	}

	if len(existingSecGroups.Resources) <= 0 {
		return
	}

	existingSecGroupGUIDs := make([]string, 0)
	for _, secGroup := range existingSecGroups.Resources {
		existingSecGroupGUIDs = append(existingSecGroupGUIDs, secGroup.GUID)
	}

	for _, entitlement := range entitlements {
		if !funk.ContainsString(existingSecGroupGUIDs, entitlement.SecurityGroupGUID) {
			DB.Delete(&entitlement)
		}
	}
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

func filterParam(req *http.Request, param string) []string {
	res := make([]string, 0)
	if isFilterAuthorized(param) {
		for _, v := range strings.Split(req.URL.Query().Get(param), ",") {
			if v != "" {
				res = append(res, v)
			}
		}
	}
	return res
}

func filterGuid(req *http.Request) string {
	pathSplit := strings.Split(req.URL.Path, "/")
	if len(pathSplit) == 4 && pathSplit[3] != "" {
		return pathSplit[3]
	}
	return ""
}

func filterNames(req *http.Request) []string {
	return filterParam(req, "names")
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
