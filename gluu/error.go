package gluu

import (
	"github.com/hashicorp/errwrap"
	"net/http"
)

type ApiError struct {
	Code    int
	Message string
}

func (e *ApiError) Error() string {
	return e.Message
}

func ErrorIs404(err error) bool {
	gluuError, ok := errwrap.GetType(err, &ApiError{}).(*ApiError)

	return ok && gluuError != nil && gluuError.Code == http.StatusNotFound
}

func ErrorIs409(err error) bool {
	gluuError, ok := errwrap.GetType(err, &ApiError{}).(*ApiError)

	return ok && gluuError != nil && gluuError.Code == http.StatusConflict
}
