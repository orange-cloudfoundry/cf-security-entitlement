package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cloudfoundry-community/gautocloud"
	"github.com/gorilla/context"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/model"

	"github.com/pkg/errors"
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

func secGoupsHandler(w http.ResponseWriter, req *http.Request) {
	if expiresAt.Before(time.Now()) {
		var config model.ConfigServer
		err := gautocloud.Inject(&config)
		if err != nil {
			return
		}
		tr := shallowDefaultTransport(config.TrustedCaCertificates, config.CloudFoundry.SkipSSLValidation)

		accessToken, refreshExpiresAt, err := AuthenticateWithExpire(config.CloudFoundry.UAAEndpoint, config.CloudFoundry.ClientID, config.CloudFoundry.ClientSecret, tr)
		if err != nil {
			_ = errors.Wrap(err, "Error when authenticate on cf")
			return
		}
		if accessToken == "" {
			_ = errors.Errorf("A pair of username/password or a pair of client_id/client_secret muste be set.")
			return
		}

		expiresAt = refreshExpiresAt
		cfclient.SetAccessToken(accessToken)
	}

	path := req.URL.Path
	if bindReqRegex.MatchString(path) && (req.Method == http.MethodPost || req.Method == http.MethodDelete) {
		bindOrUnbindSecGroup(w, req)
		return
	}
	if checkReqRegex.MatchString(path) && req.Method == http.MethodGet {
		checkBind(w, req)
		return
	}
	if findReqRegex.MatchString(path) && req.Method == http.MethodGet {
		findSecGroup(w, req)
		return
	}

	serverErrorCode(w, req, http.StatusNotImplemented, fmt.Errorf("fonction inconnue"))
}

func (SecGroupMiddleware) Schema() interface{} {
	return SecGroupConfig{}
}

func checkBind(w http.ResponseWriter, req *http.Request) {
	_, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, req, http.StatusBadRequest, err)
		return
	}
	pathSplit := strings.Split(req.URL.Path, "/")
	spaceGuid := pathSplit[6]

	space, err := cfclient.GetSpaceByGuid(spaceGuid)
	if err != nil {
		serverError(w, req, err)
		return
	}

	data := struct {
		OrganizationGUID string `json:"organization_guid"`
		IsEntitled       bool   `json:"is_entitled"`
	}{
		OrganizationGUID: space.Relationships["organization"].GUID,
		IsEntitled:       true,
	}
	b, _ := json.MarshalIndent(data, "", "  ")
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

func bindOrUnbindSecGroup(w http.ResponseWriter, req *http.Request) {
	var dataBody body
	var spaceGuid string

	userId, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, req, http.StatusBadRequest, err)
		return
	}
	path := req.URL.Path
	pathSplit := strings.Split(path, "/")
	secGroupGuid := pathSplit[3]

	if req.Method == http.MethodPost {
		buf, err := io.ReadAll(req.Body)
		if err != nil {
			_ = errors.Wrap(err, "Error reading User")
			return
		}
		if err = json.Unmarshal(buf, &dataBody); err != nil {
			_ = errors.Wrap(err, "Error unmarshalling User")
			return
		}
		if len(dataBody.Data) == 0 {
			_ = errors.Wrap(err, "Error unmarshalling User")
		}
		spaceGuid = dataBody.Data[0].GUID
	}

	if req.Method == http.MethodDelete && len(pathSplit) > 6 {
		spaceGuid = pathSplit[6]
	}

	space, err := cfclient.GetSpaceByGuid(spaceGuid)
	if err != nil {
		serverError(w, req, err)
		return
	}

	if !context.Get(req, ContextIsAdmin).(bool) {
		hasAccess, err := isUserOrgManager(userId, space.Relationships["organization"].GUID)
		if err != nil {
			serverError(w, req, err)
			return
		}
		if !hasAccess {
			serverErrorCode(w, req, http.StatusUnauthorized, fmt.Errorf("acces denied"))
			return
		}
	}
	if req.Method == http.MethodPost {
		if pathSplit[5] == "running_spaces" {
			err = cfclient.BindRunningSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				serverError(w, req, err)
				return
			}
		}
		if pathSplit[5] == "staging_spaces" {
			err = cfclient.BindStagingSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				serverError(w, req, err)
				return
			}
		}
	} else {
		if pathSplit[5] == "running_spaces" {
			err = cfclient.UnBindRunningSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				if strings.Contains(err.Error(), "UnprocessableEntity") {
					serverErrorCode(w, req, http.StatusUnprocessableEntity, fmt.Errorf("unable to unbind security group from space with guid '%s'. Ensure the space is bound to this security group", spaceGuid))
					return
				} else {
					serverError(w, req, err)
					return
				}
			}
		}
		if pathSplit[5] == "staging_spaces" {
			err = cfclient.UnBindStagingSecGroupToSpace(secGroupGuid, spaceGuid, cfclient.GetApiUrl())
			if err != nil {
				if strings.Contains(err.Error(), "UnprocessableEntity") {
					serverErrorCode(w, req, http.StatusUnprocessableEntity, fmt.Errorf("unable to unbind security group from space with guid '%s'. Ensure the space is bound to this security group", spaceGuid))
					return
				} else {
					serverError(w, req, err)
					return
				}
			}
		}
	}

}

func findSecGroup(w http.ResponseWriter, req *http.Request) {
	buffer, err := cfclient.ListAllSecGroups(req)
	if err != nil {
		serverError(w, req, err)
		return
	}
	w.Header().Add("Content-Type", "application/json")
	_, _ = w.Write(buffer)
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
