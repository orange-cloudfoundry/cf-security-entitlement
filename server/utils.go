package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccerror"
)

func serverError(w http.ResponseWriter, err error) {
	serverErrorCode(w, http.StatusInternalServerError, err)
}

func serverErrorCode(w http.ResponseWriter, code int, err error) {
	w.Header().Add("Content-Type", "application/json")
	if httpErr, ok := err.(ccerror.V3UnexpectedResponseError); ok {
		w.WriteHeader(httpErr.ResponseCode)
		b, _ := json.Marshal(ccerror.V3UnexpectedResponseError{
			ResponseCode: httpErr.ResponseCode,
			RequestIDs:   httpErr.RequestIDs,
		})
		w.Write(b)
		return
	}
	w.WriteHeader(code)
	b, _ := json.Marshal(ccerror.V3UnexpectedResponseError{
		ResponseCode: code,
		//RequestIDs:   err.Error(),
	})
	w.Write(b)
}

func isAdmin(groups []string) bool {
	for _, g := range groups {
		if g == "cloud_controller.admin" {
			return true
		}
	}
	return false
}

func isNotFoundErr(err error) bool {
	if httpErr, ok := err.(ccerror.RawHTTPStatusError); ok {
		return httpErr.StatusCode == http.StatusNotFound
	}
	return false
}

func getUserId(req *http.Request) (string, error) {

	token := req.Header.Get("Authorization")

	tokenSplit := strings.Split(token, ".")
	if len(tokenSplit) < 3 {
		return "", fmt.Errorf("Invalid token")
	}

	var userIdStruct struct {
		UserID string `json:"user_id"`
	}
	userInfo, err := base64.RawStdEncoding.DecodeString(tokenSplit[1])
	if err != nil {

		return "", fmt.Errorf("Invalid token")
	}

	err = json.Unmarshal(userInfo, &userIdStruct)
	if err != nil {
		return "", fmt.Errorf("Invalid token")
	}
	if userIdStruct.UserID == "" {
		return "", fmt.Errorf("missing user information")
	}
	return userIdStruct.UserID, nil
}
