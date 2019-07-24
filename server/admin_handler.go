package main

import (
	"encoding/json"
	"fmt"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"net/http"
)

func handleEntitleSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var entitlement model.EntitlementSecGroup
	err := json.NewDecoder(req.Body).Decode(&entitlement)
	if err != nil {
		serverError(w, err)
		return
	}
	if entitlement.OrganizationGUID == "" || entitlement.SecurityGroupGUID == "" {
		serverErrorCode(w, http.StatusBadRequest, fmt.Errorf("organization_guid or security_group_guid not found"))
		return
	}
	var tmpEntitlement model.EntitlementSecGroup
	DB.Where(&entitlement).First(&tmpEntitlement)
	if tmpEntitlement.OrganizationGUID != "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusCreated)
	DB.Create(&entitlement)
}

func handleRevokeSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	var entitlement model.EntitlementSecGroup
	err := json.NewDecoder(req.Body).Decode(&entitlement)
	if err != nil {
		panic(err)
	}

	if entitlement.OrganizationGUID == "" || entitlement.SecurityGroupGUID == "" {
		serverErrorCode(w, http.StatusBadRequest, fmt.Errorf("organization_guid or security_group_guid not found"))
		return
	}

	secGroup, err := client.GetSecGroup(entitlement.SecurityGroupGUID)
	if err != nil {
		panic(err)
	}
	spaces, err := secGroup.ListSpaceResources()
	if err != nil {
		panic(err)
	}
	for _, space := range spaces {
		if space.Entity.OrganizationGuid == entitlement.OrganizationGUID {
			serverErrorCode(w, http.StatusBadRequest, fmt.Errorf("There is still bindings in this organization, please remove all bindings before revoke"))
			return
		}
	}

	DB.Delete(&entitlement)
}

func handleListSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	entitlements := make([]model.EntitlementSecGroup, 0)
	DB.Order("security_group_guid").Find(&entitlements)
	b, _ := json.Marshal(entitlements)
	w.Header().Add("Content-Type", "application/json")
	w.Write(b)
}
