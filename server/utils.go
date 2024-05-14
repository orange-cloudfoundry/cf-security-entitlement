package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/client"
	"github.com/prometheus/client_golang/prometheus"
	log "github.com/sirupsen/logrus"
)

func serverError(w http.ResponseWriter, r *http.Request, err error) {
	serverErrorCode(w, r, http.StatusInternalServerError, err)
}

func serverErrorCode(w http.ResponseWriter, r *http.Request, code int, err error) {
	log.Error(err)
	w.Header().Add("Content-Type", "application/json")

	var httpErr client.CloudFoundryErrorV3
	if errors.As(err, &httpErr) {
		w.WriteHeader(httpErr.Code)

		b, _ := json.Marshal(client.CloudFoundryErrorV3{
			Code:   httpErr.Code,
			Title:  httpErr.Title,
			Detail: httpErr.Detail,
		})
		w.Write(b)
		return
	}
	w.WriteHeader(code)

	b, _ := json.Marshal(client.CloudFoundryErrorV3{
		Code:   code,
		Title:  http.StatusText(code),
		Detail: err.Error(),
	})
	w.Write(b)
	gHttpTotal.With(prometheus.Labels{
		"endpoint": r.URL.Path,
		"method":   r.Method,
		"status":   fmt.Sprintf("%d", code),
	}).Inc()
}

/*
func isAdmin(groups []string) bool {
	for _, g := range groups {
		if g == "cloud_controller.admin" {
			return true
		}
	}
	return false
}*/

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

func getSecretEncoded(key string, signingMethod jwt.SigningMethod) (interface{}, error) {
	bKey := []byte(key)
	if strings.HasPrefix(signingMethod.Alg(), "HS") {
		return bKey, nil
	}
	if strings.HasPrefix(signingMethod.Alg(), "ES") {
		encSecret, err := jwt.ParseECPublicKeyFromPEM(bKey)
		if err == nil {
			return encSecret, nil
		}
		return jwt.ParseECPrivateKeyFromPEM(bKey)
	}
	encSecret, err := jwt.ParseRSAPublicKeyFromPEM(bKey)
	if err == nil {
		return encSecret, nil
	}
	return jwt.ParseRSAPrivateKeyFromPEM(bKey)
}
