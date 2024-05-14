package model

type JsonError struct {
	ErrMessage string `json:"error"`
}

func (e JsonError) Error() string {
	return e.ErrMessage
}
