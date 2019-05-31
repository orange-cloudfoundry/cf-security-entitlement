package model

import (
	"encoding/json"
	"fmt"
)

type JsonError struct {
	ErrMessage string `json:"error"`
}

func (e JsonError) Error() string {
	return e.ErrMessage
}

func ParseJsonError(b []byte) error {
	var jsonError JsonError
	err := json.Unmarshal(b, &jsonError)
	if err != nil {
		return fmt.Errorf(string(b))
	}
	return jsonError
}
