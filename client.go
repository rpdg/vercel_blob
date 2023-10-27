package vercel_blob

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

const (
	BLOB_API_VERSION = "4"
	DEFAULT_BASE_URL = "https://blob.vercel-storage.com"
)

type VercelBlobClient struct {
	tokenProvider TokenProvider
	baseURL       string
	apiVersion    string
}

type BlobApiErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type BlobApiError struct {
	Error BlobApiErrorDetail `json:"error"`
}

func NewVercelBlobClient() *VercelBlobClient {
	return &VercelBlobClient{
		baseURL:    DEFAULT_BASE_URL,
		apiVersion: BLOB_API_VERSION,
	}
}

func NewVercelBlobClientExternal(tokenProvider TokenProvider) *VercelBlobClient {
	return &VercelBlobClient{
		tokenProvider: tokenProvider,
		baseURL:       DEFAULT_BASE_URL,
		apiVersion:    BLOB_API_VERSION,
	}
}

func (c *VercelBlobClient) getBaseURL() string {
	baseURL := os.Getenv("VERCEL_BLOB_API_URL")
	if baseURL == "" {
		baseURL = os.Getenv("NEXT_PUBLIC_VERCEL_BLOB_API_URL")
	}
	if baseURL == "" {
		return DEFAULT_BASE_URL
	}
	return baseURL
}

func (c *VercelBlobClient) getAPIURL(pathname string) string {
	base, _ := url.Parse(c.baseURL)
	base.Path = pathname
	return base.String()
}

func (c *VercelBlobClient) getAPIVersion() string {
	version := os.Getenv(BLOB_API_VERSION)
	if version == "" {
		return BLOB_API_VERSION
	}
	return version
}

func (c *VercelBlobClient) addAPIVersionHeader(req *http.Request) {
	req.Header.Set("x-api-version", c.apiVersion)
}

func (c *VercelBlobClient) addAuthorizationHeader(req *http.Request, operation, pathname string) error {
	var token string
	if c.tokenProvider != nil {
		token, _ = c.tokenProvider.GetToken(operation, pathname)
	} else {
		token = os.Getenv("BLOB_READ_WRITE_TOKEN")
	}

	if token == "" {
		return ErrNotAuthenticated
	}

	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

func (c *VercelBlobClient) handleError(resp *http.Response) error {
	if resp.StatusCode >= 500 {
		return NewUnknownError(resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	var errResp BlobApiError
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
		return err
	}

	switch errResp.Error.Code {
	case "store_suspended":
		return ErrStoreSuspended
	case "forbidden":
		return ErrForbidden
	case "not_found":
		return ErrBlobNotFound
	case "store_not_found":
		return ErrStoreNotFound
	case "bad_request":
		return ErrBadRequest(errResp.Error.Message)
	default:
		return NewUnknownError(resp.StatusCode, errResp.Error.Message)
	}
}

type ListBlobResultBlob struct {
	URL        string    `json:"url"`
	PathName   string    `json:"pathname"`
	Size       uint64    `json:"size"`
	UploadedAt time.Time `json:"uploadedAt"`
}

type ListBlobResult struct {
	Blobs   []ListBlobResultBlob `json:"blobs"`
	Cursor  string               `json:"cursor"`
	HasMore bool                 `json:"hasMore"`
}

type ListCommandOptions struct {
	Limit  uint64
	Prefix string
	Cursor string
}

type PutCommandOptions struct {
	AddRandomSuffix    bool
	CacheControlMaxAge uint64
	ContentType        string
}

type Range struct {
	Start uint
	End   uint
}

type DownloadCommandOptions struct {
	ByteRange *Range
}

type PutResult struct {
	URL         string `json:"url"`
	Path        string `json:"pathname"`
	ContentType string `json:"contentType"`
}

type HeadBlobResult struct {
	URL          string    `json:"url"`
	Size         uint64    `json:"size"`
	UploadedAt   time.Time `json:"uploadedAt"`
	Path         string    `json:"pathname"`
	ContentType  string    `json:"contentType"`
	CacheControl string    `json:"cacheControl"`
}

func (c *VercelBlobClient) List(options ListCommandOptions) (*ListBlobResult, error) {

	req, err := http.NewRequest(http.MethodGet, c.baseURL, nil)
	if err != nil {
		return nil, err
	}

	q := req.URL.Query()
	if options.Limit > 0 {
		q.Add("limit", strconv.FormatUint(options.Limit, 10))
	}
	if options.Prefix != "" {
		q.Add("prefix", options.Prefix)
	}
	if options.Cursor != "" {
		q.Add("cursor", options.Cursor)
	}
	req.URL.RawQuery = q.Encode()

	c.addAPIVersionHeader(req)
	err = c.addAuthorizationHeader(req, "list", "")
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var result ListBlobResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *VercelBlobClient) Put(pathname string, body io.Reader, options PutCommandOptions) (*PutResult, error) {

	if pathname == "" {
		return nil, NewInvalidInputError("pathname")
	}

	apiUrl := c.getAPIURL(pathname)

	req, err := http.NewRequest(http.MethodPut, apiUrl, body)
	if err != nil {
		return nil, err
	}

	c.addAPIVersionHeader(req)
	err = c.addAuthorizationHeader(req, "put", pathname)
	if err != nil {
		return nil, err
	}

	if !options.AddRandomSuffix {
		req.Header.Set("X-Add-Random-Suffix", "0")
	}
	if options.ContentType != "" {
		req.Header.Set("X-Content-Type", options.ContentType)
	}
	if options.CacheControlMaxAge > 0 {
		req.Header.Set("X-Cache-Control-Max-Age", strconv.FormatUint(options.CacheControlMaxAge, 10))
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var result PutResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *VercelBlobClient) Head(pathname string) (*HeadBlobResult, error) {

	apiUrl := c.getAPIURL(pathname)

	req, err := http.NewRequest(http.MethodGet, apiUrl, nil)
	if err != nil {
		return nil, err
	}
	c.addAPIVersionHeader(req)
	err = c.addAuthorizationHeader(req, "put", pathname)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrBlobNotFound
	} else if resp.StatusCode != http.StatusOK {
		return nil, c.handleError(resp)
	}

	var result HeadBlobResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (c *VercelBlobClient) Delete(urlPath string) error {

	apiUrl := c.getAPIURL("/delete")

	req, err := http.NewRequest(http.MethodPost, apiUrl, nil)
	if err != nil {
		return err
	}

	c.addAPIVersionHeader(req)
	err = c.addAuthorizationHeader(req, "delete", urlPath)
	if err != nil {
		return err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return c.handleError(resp)
	}

	return nil
}

func (c *VercelBlobClient) Download(urlPath string, options DownloadCommandOptions) ([]byte, error) {

	req, err := http.NewRequest(http.MethodGet, urlPath, nil)
	if err != nil {
		return nil, err
	}

	c.addAPIVersionHeader(req)
	err = c.addAuthorizationHeader(req, "download", urlPath)
	if err != nil {
		return nil, err
	}

	if options.ByteRange != nil {
		start := options.ByteRange.Start
		end := options.ByteRange.End
		if start == end {
			return []byte{}, nil
		}
		req.Header.Set("range", fmt.Sprintf("bytes=%d-%d", start, end))
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusPartialContent {
		return nil, c.handleError(resp)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
