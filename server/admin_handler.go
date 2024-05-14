package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3/constant"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/model"

	"github.com/gorilla/context"
)

// Deprecated: Entitlements were deleted
func handleEntitleSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	if !context.Get(req, ContextIsAdmin).(bool) {
		serverErrorCode(w, req, http.StatusForbidden, fmt.Errorf("forbidden"))
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// Deprecated: Entitlements were deleted
func handleRevokeSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	if !context.Get(req, ContextIsAdmin).(bool) {
		serverErrorCode(w, req, http.StatusForbidden, fmt.Errorf("forbidden"))
		return
	}
}

// Deprecated: Entitlements were deleted
func handleListSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	if !context.Get(req, ContextIsAdmin).(bool) {
		serverErrorCode(w, req, http.StatusForbidden, fmt.Errorf("forbidden"))
		return
	}
	w.Header().Add("Content-Type", "application/json")
	w.Write([]byte("[]"))
}

// bind or unbind a security group to a space
func handleBindSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()

	var binding model.BindingParams
	err := json.NewDecoder(req.Body).Decode(&binding)
	if err != nil {
		serverError(w, req, err)
		return
	}

	userId, err := getUserId(req)
	if err != nil {
		serverErrorCode(w, req, http.StatusBadRequest, err)
		return
	}

	space, err := cfclient.GetSpaceByGuid(binding.SpaceGUID)
	if err != nil {
		serverError(w, req, err)
		return
	}

	orgGuid := space.Relationships[constant.RelationshipTypeOrganization].GUID

	if !context.Get(req, ContextIsAdmin).(bool) {
		hasAccess, err := isUserOrgManager(userId, orgGuid)
		if err != nil {
			serverError(w, req, err)
			return
		}
		if !hasAccess {
			serverErrorCode(w, req, http.StatusUnauthorized, fmt.Errorf(""))
			return
		}
	}

	if req.Method == http.MethodDelete {
		err = cfclient.UnBindSecurityGroup(binding.SecurityGroupGUID, binding.SpaceGUID, cfclient.GetApiUrl())
	} else {
		err = cfclient.BindSecurityGroup(binding.SecurityGroupGUID, binding.SpaceGUID, cfclient.GetApiUrl())
	}
	if err != nil {
		serverError(w, req, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}
