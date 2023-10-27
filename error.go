package vercel_blob

import (
	"fmt"
)

// VercelBlobError 是本package所有错误的接口
type VercelBlobError struct {
	Msg  string
	Code string
}

func (e VercelBlobError) Error() string {
	return e.Msg
}

var (
	// ErrNotAuthenticated 没有认证
	ErrNotAuthenticated = &VercelBlobError{
		Msg:  "No authentication token. Expected environment variable BLOB_READ_WRITE_TOKEN to contain a token",
		Code: "not_authenticated",
	}

	// ErrBadRequest 请求错误
	ErrBadRequest = func(msg string) VercelBlobError {
		return VercelBlobError{
			Msg:  fmt.Sprintf("Invalid request: %s", msg),
			Code: "bad_request",
		}
	}

	// ErrForbidden 禁止访问
	ErrForbidden = &VercelBlobError{
		Msg:  "Access denied, please provide a valid token for this resource",
		Code: "forbidden",
	}

	// ErrStoreNotFound 存储不存在
	ErrStoreNotFound = &VercelBlobError{
		Msg:  "The requested store does not exist",
		Code: "store_not_found",
	}

	// ErrStoreSuspended 存储暂停
	ErrStoreSuspended = &VercelBlobError{
		Msg:  "The requested store has been suspended",
		Code: "store_suspended",
	}

	// ErrBlobNotFound Blob不存在
	ErrBlobNotFound = &VercelBlobError{
		Msg:  "The requested blob does not exist",
		Code: "not_found",
	}
)

// NewUnknownError 创建未知错误
func NewUnknownError(statusCode int, message string) VercelBlobError {
	return VercelBlobError{
		Msg:  fmt.Sprintf("Unknown error, please visit https://vercel.com/help (%d): %s", statusCode, message),
		Code: "unknown_error",
	}
}

// NewInvalidInputError 创建输入错误
func NewInvalidInputError(field string) VercelBlobError {
	return VercelBlobError{
		Msg:  fmt.Sprintf("%s is required", field),
		Code: "invalid_input",
	}
}

// Result 自定义Result类型
type Result struct {
	Value interface{}
	Err   error
}

// 辅助方法用于返回Result
func Ok(value interface{}) Result {
	return Result{Value: value, Err: nil}
}

func Err(err error) Result {
	return Result{Value: nil, Err: err}
}
