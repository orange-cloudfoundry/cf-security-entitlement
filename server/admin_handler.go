package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
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
	client := &http.Client{Transport: &tr}

	Request, err := http.NewRequest(http.MethodGet, apiUrl+"/v3/security_groups/"+entitlement.SecurityGroupGUID, nil)
	if err != nil {
		panic(err)
	}

	Request.Header.Add("Authorization", accessToken)

	resp, err := client.Do(Request)
	if err != nil {
		panic(err)
	}

	defer resp.Body.Close()

	buf, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err = json.Unmarshal(buf, &secGroup); err != nil {
		serverErrorCode(w, http.StatusBadRequest, fmt.Errorf("Error unmarshaling Security Group"))
		return
	}

	secGroupWithOrg, err := cfclient.ListSpaceResources(secGroup)
	if err != nil {
		panic(err)
	}

	for _, space := range secGroupWithOrg.Relationships.Running_spaces.Data {
		if space.OrgGUID == entitlement.OrganizationGUID {
			serverErrorCode(w, http.StatusUnprocessableEntity, fmt.Errorf("There is still bindings in this organization, please remove all bindings before revoke"))
			return
		}
	}

	for _, space := range secGroupWithOrg.Relationships.Staging_spaces.Data {
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
