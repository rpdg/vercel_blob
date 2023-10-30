package vercel_blob

import (
	"fmt"
)

// VercelBlobError will be the type of all errors raised by this crate.
type VercelBlobError struct {
	Msg  string
	Code string
}

func (e VercelBlobError) Error() string {
	return e.Msg
}

// All errors raised by this crate will be instances of VercelBlobError
var (
	ErrNotAuthenticated = &VercelBlobError{
		Msg:  "No authentication token. Expected environment variable BLOB_READ_WRITE_TOKEN to contain a token",
		Code: "not_authenticated",
	}

	ErrBadRequest = func(msg string) VercelBlobError {
		return VercelBlobError{
			Msg:  fmt.Sprintf("Invalid request: %s", msg),
			Code: "bad_request",
		}
	}

	ErrForbidden = &VercelBlobError{
		Msg:  "Access denied, please provide a valid token for this resource",
		Code: "forbidden",
	}

	ErrStoreNotFound = &VercelBlobError{
		Msg:  "The requested store does not exist",
		Code: "store_not_found",
	}

	ErrStoreSuspended = &VercelBlobError{
		Msg:  "The requested store has been suspended",
		Code: "store_suspended",
	}

	ErrBlobNotFound = &VercelBlobError{
		Msg:  "The requested blob does not exist",
		Code: "not_found",
	}
)

func NewUnknownError(statusCode int, message string) VercelBlobError {
	return VercelBlobError{
		Msg:  fmt.Sprintf("Unknown error, please visit https://vercel.com/help (%d): %s", statusCode, message),
		Code: "unknown_error",
	}
}

func NewInvalidInputError(field string) VercelBlobError {
	return VercelBlobError{
		Msg:  fmt.Sprintf("%s is required", field),
		Code: "invalid_input",
	}
}
