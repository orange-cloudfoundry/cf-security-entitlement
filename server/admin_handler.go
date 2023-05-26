package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
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
	var secGroup client.SecurityGroup
	err := json.NewDecoder(req.Body).Decode(&entitlement)
	if err != nil {
		panic(err)
	}

	if entitlement.OrganizationGUID == "" || entitlement.SecurityGroupGUID == "" {
		serverErrorCode(w, http.StatusBadRequest, fmt.Errorf("organization_guid or security_group_guid not found"))
		return
	}

	apiUrl := cfclient.GetApiUrl()

	accessToken := req.Header.Get("Authorization")
	tr := cfclient.GetTransport()
	cfClient := &http.Client{Transport: &tr}

	Request, err := http.NewRequest(http.MethodGet, apiUrl+"/v3/security_groups/"+entitlement.SecurityGroupGUID, nil)
	if err != nil {
		panic(err)
	}

	Request.Header.Add("Authorization", accessToken)

	resp, err := cfClient.Do(Request)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = json.Unmarshal(buf, &secGroup); err != nil {
		serverErrorCode(w, http.StatusBadRequest, fmt.Errorf("Error unmarshaling Security Group"))
		return
	}

	err = cfclient.AddSecGroupRelationShips(&secGroup)
	if err != nil {
		panic(err)
	}

	for _, space := range secGroup.Relationships.Running_Spaces.Data {
		if space.OrgGUID == entitlement.OrganizationGUID {
			serverErrorCode(w, http.StatusUnprocessableEntity, fmt.Errorf("There is still bindings in this organization, please remove all bindings before revoke"))
			return
		}
	}

	for _, space := range secGroup.Relationships.Staging_Spaces.Data {
		if space.OrgGUID == entitlement.OrganizationGUID {
			serverErrorCode(w, http.StatusUnprocessableEntity, fmt.Errorf("There is still bindings in this organization, please remove all bindings before revoke"))
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

func handleCleanSecGroup(w http.ResponseWriter, req *http.Request) {
	defer req.Body.Close()
	deleted := make([]model.EntitlementSecGroup, 0)
	var entitlements []model.EntitlementSecGroup
	DB.Order("security_group_guid").Find(&entitlements)

	apiUrl := cfclient.GetApiUrl()

	accessToken := req.Header.Get("Authorization")
	tr := cfclient.GetTransport()
	cfClient := &http.Client{Transport: &tr}

	for _, entitlement := range entitlements {
		Request, err := http.NewRequest(http.MethodGet, apiUrl+"/v3/security_groups/"+entitlement.SecurityGroupGUID, nil)
		if err != nil {
			panic(err)
		}

		Request.Header.Add("Authorization", accessToken)

		resp, err := cfClient.Do(Request)
		if err != nil {
			panic(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			DB.Delete(entitlement.SecurityGroupGUID, entitlement.OrganizationGUID)
			deleted = append(deleted, entitlement)
		}
		b, _ := json.Marshal(deleted)
		w.Header().Add("Content-Type", "application/json")
		w.Write(b)
	}

}
