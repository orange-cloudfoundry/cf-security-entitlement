package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/context"

	"github.com/golang-jwt/jwt/v5"
	"github.com/orange-cloudfoundry/cf-security-entitlement/v2/model"
	"github.com/pkg/errors"
)

const ContextIsAdmin = "isAdmin"

type AuthToken struct {
	Type  string
	Value string
}

type ScopeClaims struct {
	Scope []string `json:"scope"`
	jwt.RegisteredClaims
}

type Auth struct {
	Jwt *model.JWT
}

func (c ScopeClaims) Validate() error {
	if c.Scope == nil {
		return errors.New("unexpected token claims")
	}
	return nil
}

func (c ScopeClaims) IsAdmin() bool {
	if c.Scope != nil {
		for _, scope := range c.Scope {
			if scope == "cloud_controller.admin" {
				return true
			}
		}
	}
	return false
}

func NewAuth(jwt *model.JWT) *Auth {
	return &Auth{
		Jwt: jwt,
	}
}

func (ah *Auth) authHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		token, err := ExtractToken(r)
		if err != nil {
			serverErrorCode(w, r, http.StatusBadRequest, err)
			return
		}
		method := jwt.GetSigningMethod(ah.Jwt.Alg)
		if method == nil {
			serverErrorCode(w, r, http.StatusBadRequest, fmt.Errorf("invalid jwt alg '%s'", ah.Jwt.Alg))
			return
		}

		claims := &ScopeClaims{}

		tkn, err := jwt.ParseWithClaims(token.Value, claims, func(token *jwt.Token) (any, error) {
			return getSecretEncoded(ah.Jwt.Secret, method)
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				serverErrorCode(w, r, http.StatusUnauthorized, fmt.Errorf("JWT : invalid signature"))
				return
			}
			serverErrorCode(w, r, http.StatusUnauthorized, err)
			return
		}
		if !tkn.Valid {
			serverErrorCode(w, r, http.StatusUnauthorized, err)
			return
		}

		err = claims.Validate()
		if err != nil {
			serverErrorCode(w, r, http.StatusUnauthorized, err)
			return
		}

		context.Set(r, ContextIsAdmin, claims.IsAdmin())
		next.ServeHTTP(w, r)
	})
}

func ExtractToken(r *http.Request) (*AuthToken, error) {
	token := r.Header.Get("Authorization")
	if token == "" {
		return nil, fmt.Errorf("missing authorization header")
	}

	parts := strings.SplitN(token, " ", 2)
	if (len(parts) != 2) && (!strings.EqualFold(parts[0], "Bearer")) {
		return nil, fmt.Errorf("unknown token format")
	}

	return &AuthToken{
		Type:  "Bearer",
		Value: strings.TrimSpace(parts[1]),
	}, nil
}
