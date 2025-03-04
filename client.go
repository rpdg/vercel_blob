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
	BLOB_API_VERSION = "9"
	DEFAULT_BASE_URL = "https://blob.vercel-storage.com"
)

type VercelBlobClient struct {
	// A token provider to use to obtain a token to authenticate with the API
	tokenProvider TokenProvider
	// The server URL to use.  This is not normally needed but can be used for testing purposes.
	baseURL string
	// The API version of the client
	apiVersion string
}

type BlobApiErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type BlobApiError struct {
	Error BlobApiErrorDetail `json:"error"`
}

// NewVercelBlobClient creates a new client for use inside a Vercel function
func NewVercelBlobClient() *VercelBlobClient {
	return &VercelBlobClient{
		baseURL:    DEFAULT_BASE_URL,
		apiVersion: BLOB_API_VERSION,
	}
}

// NewVercelBlobClientExternal creates a new client for use outside of Vercel
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

// ListBlobResultBlob is details about a blob that are returned by the list operation
type ListBlobResultBlob struct {
	// The URL to download the blob
	URL string `json:"url"`
	// The pathname of the blob
	PathName string `json:"pathname"`
	// The size of the blob in bytes
	Size uint64 `json:"size"`
	// The time the blob was uploaded
	UploadedAt time.Time `json:"uploadedAt"`
}

// ListBlobResult is the response from the list operation
type ListBlobResult struct {
	// A list of blobs found by the operation
	Blobs []ListBlobResultBlob `json:"blobs"`
	// A cursor that can be used to page results
	Cursor string `json:"cursor"`
	// True if there are more results available
	HasMore bool `json:"hasMore"`
}

// ListCommandOptions is options for the list operation
//
// The limit option can be used to limit the number of results returned.
// If the limit is reached then response will have has_more set to true
// and the cursor can be used to get the next page of results.
type ListCommandOptions struct {
	// The maximum number of results to return
	Limit uint64
	// A prefix to filter results
	Prefix string
	// A cursor (returned from a previous list call) used to page results
	Cursor string
}

// PutCommandOptions is options for the put operation
//
// By default uploaded files are assigned a URL with a random suffix.  This
// ensures that no put operation will overwrite an existing file.  The url
// returned in the response can be used to later download the file.
//
// If predictable URLs are needed then add_random_suffix can be set to false
// to disable this behavior.  If dsiabled then sequential writes to the same
// pathname will overwrite each other.
type PutCommandOptions struct {
	AddRandomSuffix    bool
	CacheControlMaxAge uint64
	ContentType        string
}

type Range struct {
	Start uint
	End   uint
}

// DownloadCommandOptions is options for the download operation
type DownloadCommandOptions struct {
	// The range of bytes to download.  If not specified then the entire blob
	// is downloaded.  The start of the range must be less than the # of bytes
	// in the blob or an error will be returned.  The end of the range may be
	// greater than the number of bytes in the blob.
	ByteRange *Range
}

// PutBlobPutResult is the response from the put operation
type PutBlobPutResult struct {
	// The URL to download the blob
	URL string `json:"url"`
	// The pathname of the blob
	Pathname string `json:"pathname"`
	// The content type of the blob
	ContentType string `json:"contentType"`
	// The content disposition of the blob
	ContentDisposition string `json:"contentDisposition"`
}

// HeadBlobResult is response from the head operation
type HeadBlobResult struct {
	// The URL to download the blob
	URL string `json:"url"`
	// The size of the blob in bytes
	Size uint64 `json:"size"`
	// The time the blob was uploaded
	UploadedAt time.Time `json:"uploadedAt"`
	// The pathname of the blob
	Pathname string `json:"pathname"`
	// The content type of the blob
	ContentType string `json:"contentType"`
	// The content disposition of the blob
	ContentDisposition string `json:"contentDisposition"`
	// The cache settings for the blob
	CacheControl string `json:"cacheControl"`
}

// List files in the blob store
//
// # Arguments
//
//   - `options` - Options for the list operation
//
// # Returns
//
// The response from the list operation
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

// Put uploads a file to the blob store
//
// # Arguments
//
//   - `pathname` - The destination pathname for the uploaded file
//   - `body` - The contents of the file
//   - `options` - Options for the put operation
//
// # Returns
//
// The response from the put operation.  This includes a URL that can
// be used to later download the blob.
func (c *VercelBlobClient) Put(pathname string, body io.Reader, options PutCommandOptions) (*PutBlobPutResult, error) {

	if len(pathname) == 0 {
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

	var result PutBlobPutResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Head gets the metadata for a file in the blob store
//
// # Arguments
//
//   - `pathname` - The URL of the file to get metadata for.  This should be the same URL that is used
//     to download the file.
//   - `options` - Options for the head operation
//
// # Returns
//
// If the file exists then the metadata for the file is returned.  If the file does not exist
// then None is returned.
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

// Delete a blob from the blob store
//
// # Arguments
//
//   - `urlPath` - The URL of the file to delete.  This should be the same URL that is used
//     to download the file.
//   - `options` - Options for the del operation
//
// # Returns
//
// None
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

// Copy copies the file at the given `fromUrl` to the path `toPath`.
//
// # Arguments
//
//   - `fromUrl` - Must be a valid URL of the existed file
//   - `toPath` - The destination pathname
//   - `options` - Options for the put operation
//
// # Returns
//
// The response from the put operation.  This includes a URL that can
// be used to later download the blob.
func (c *VercelBlobClient) Copy(fromUrl, toPath string, options PutCommandOptions) (*PutBlobPutResult, error) {
	if len(fromUrl) == 0 {
		return nil, NewInvalidInputError("fromUrl")
	}

	if len(toPath) == 0 {
		return nil, NewInvalidInputError("toPath")
	}

	apiUrl := c.getAPIURL(toPath)

	req, err := http.NewRequest(http.MethodPut, apiUrl, nil)
	if err != nil {
		return nil, err
	}

	req.URL.Query().Add("fromUrl", fromUrl)

	c.addAPIVersionHeader(req)
	err = c.addAuthorizationHeader(req, "put", toPath)
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

	var result PutBlobPutResult
	if err = json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

// Download a blob from the blob store
//
// # Arguments
//
//   - `urlPath` - The URL of the file to download.
//   - `options` - Options for the download operation
//
// # Returns
//
// The contents of the file
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
