package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cloudfoundry-community/go-cfclient"
	"net/http"
	"strings"
)

func serverError(w http.ResponseWriter, err error) {
	serverErrorCode(w, http.StatusInternalServerError, err)
}

func serverErrorCode(w http.ResponseWriter, code int, err error) {
	w.Header().Add("Content-Type", "application/json")
	if httpErr, ok := err.(cfclient.CloudFoundryError); ok {
		w.WriteHeader(httpErr.Code)
		b, _ := json.Marshal(cfclient.CloudFoundryError{
			Code:        httpErr.Code,
			ErrorCode:   httpErr.ErrorCode,
			Description: httpErr.Description,
		})
		w.Write(b)
		return
	}
	w.WriteHeader(code)
	b, _ := json.Marshal(cfclient.CloudFoundryError{
		Code:        code,
		ErrorCode:   http.StatusText(code),
		Description: err.Error(),
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
	if httpErr, ok := err.(cfclient.CloudFoundryHTTPError); ok {
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
