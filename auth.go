package vercel_blob

import (
	"os"
)

/// A trait for providing a token to authenticate with the Vercel Blob Storage API.
///
/// If your code is running inside a Vercel function then you will not need this.
///
/// If your code is running outside of Vercel (e.g. a client application) then you will
/// need to obtain a token from your Vercel application.  You can create a route
/// to provide short-term tokens to authenticated users.  This trait allows you
/// to connect to that route (or use some other method to obtain a token).
///
/// The operation (e.g. list, put, download) and pathname (e.g. foo/bar.txt) are
/// provided in case fine-grained authorization is required.  For operations that
/// use the full URL (download / del) the pathname will be the URL.

// TokenProvider 定义了获取认证token的接口
type TokenProvider interface {
	GetToken(operation string, pathname string) (string, error)
}

// GetToken 从provider获取token,如果为空则从环境变量读取
func GetToken(provider TokenProvider, operation, pathname string) (string, error) {
	if provider != nil {
		return provider.GetToken(operation, pathname)
	}
	// 默认从环境变量读取
	token := os.Getenv("BLOB_READ_WRITE_TOKEN")
	if token == "" {
		return "", ErrNotAuthenticated
	}
	return token, nil
}

// EnvTokenProvider 从环境变量读取token
type EnvTokenProvider struct {
	token string
}

// GetToken 实现TokenProvider接口
func (p *EnvTokenProvider) GetToken(operation, pathname string) (string, error) {
	if p.token != "" {
		return p.token, nil
	} else {
		envToken := os.Getenv("BLOB_READ_WRITE_TOKEN")
		if envToken != "" {
			return envToken, nil
		} else {
			return "", ErrNotAuthenticated
		}
	}
}

// NewEnvTokenProvider 从环境变量构造EnvTokenProvider
func NewEnvTokenProvider(envVar string) (*EnvTokenProvider, error) {
	token, exists := os.LookupEnv(envVar)
	if !exists {
		return nil, ErrNotAuthenticated
	}
	return &EnvTokenProvider{token}, nil
}
