package grequests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/http/cookiejar"
	urlpkg "net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"
)

const (
	Ver = "0.1" // grequests version

	DefaultTimeout = 120 * time.Second // default timeout
	ContentType    = "Content-Type"
	TypeForm       = "application/x-www-form-urlencoded"
	TypeJSON       = "application/json"

	// HTTP method
	MethodGet     = "GET"
	MethodHead    = "HEAD"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodPatch   = "PATCH"
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
	MethodOptions = "OPTIONS"
	MethodTrace   = "TRACE"
)

var std = New()

type (
	// Definition of grequests client.
	Client struct {
		httpClient *http.Client
		method     string
		url        string
		params     Value
		form       Value
		json       Data
		headers    Value
		cookies    []*http.Cookie
		files      []*File
		mux        *sync.Mutex
		withLock   bool
	}

	// Wrapper of HTTP response and request error.
	Response struct {
		R   *http.Response
		Err error
	}

	// Definition of params, headers, form-data, etc.
	Value map[string]string
	// Definition of JSON.
	Data map[string]interface{}

	// Definition of multipart-data.
	File struct {
		FieldName string
		FileName  string
		FilePath  string
	}
)

// Get gets the value from a map by the given key.
func (v Value) Get(key string) string {
	return v[key]
}

// Set sets a kv pair into a map.
func (v Value) Set(key string, value string) {
	v[key] = value
}

// Del deletes the value related to the given key from a map.
func (v Value) Del(key string) {
	delete(v, key)
}

// Get gets the value from a map by the given key.
func (d Data) Get(key string) interface{} {
	return d[key]
}

// Set sets a kv pair into a map.
func (d Data) Set(key string, value interface{}) {
	d[key] = value
}

// Del deletes the value related to the given key from a map.
func (d Data) Del(key string) {
	delete(d, key)
}

// New constructors and returns a new client.
func New() *Client {
	c := &Client{
		httpClient: http.DefaultClient,
		params:     make(Value),
		form:       make(Value),
		json:       make(Data),
		headers:    make(Value),
		mux:        new(sync.Mutex),
	}

	jar, _ := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	c.httpClient.Jar = jar
	c.httpClient.Transport = http.DefaultTransport
	c.httpClient.Timeout = DefaultTimeout

	c.headers.Set("User-Agent", "grequests "+Ver)
	return c
}

// WithTransport calls std.WithTransport to set transport.
func WithTransport(transport http.RoundTripper) *Client {
	return std.WithTransport(transport)
}

// WithTransport sets transport for the HTTP client.
func (c *Client) WithTransport(transport http.RoundTripper) *Client {
	c.httpClient.Transport = transport
	return c
}

// WithRedirectPolicy calls std.WithRedirectPolicy to set redirect policy.
func WithRedirectPolicy(policy func(req *http.Request, via []*http.Request) error) *Client {
	return std.WithRedirectPolicy(policy)
}

// WithRedirectPolicy sets redirect policy for the HTTP client
func (c *Client) WithRedirectPolicy(policy func(req *http.Request, via []*http.Request) error) *Client {
	c.httpClient.CheckRedirect = policy
	return c
}

// WithCookieJar call std.WithCookieJar to set cookie jar.
func WithCookieJar(jar http.CookieJar) *Client {
	return std.WithCookieJar(jar)
}

// WithCookieJar sets cookie jar for the HTTP client.
func (c *Client) WithCookieJar(jar http.CookieJar) *Client {
	c.httpClient.Jar = jar
	return c
}

// WithTimeout calls std.WithTimeout to set timeout.
func WithTimeout(timeout time.Duration) *Client {
	return std.WithTimeout(timeout)
}

// WithTimeout set timeout for the HTTP client.
func (c *Client) WithTimeout(timeout time.Duration) *Client {
	c.httpClient.Timeout = timeout
	return c
}

// AppendClientCertificates calls std.AppendClientCertificates to append client certificates.
func AppendClientCertificates(certs ...tls.Certificate) *Client {
	return std.AppendClientCertificates(certs...)
}

// AppendClientCertificates appends client certificates for the HTTP client.
func (c *Client) AppendClientCertificates(certs ...tls.Certificate) *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	transport.TLSClientConfig.Certificates = append(transport.TLSClientConfig.Certificates, certs...)
	return c
}

// AppendRootCAs calls std.AppendRootCAs to append RootCAs.
func AppendRootCAs(pemFilePath string) *Client {
	return std.AppendRootCAs(pemFilePath)
}

// AppendRootCAs appends RootCAs for the HTTP client.
func (c *Client) AppendRootCAs(pemFilePath string) *Client {
	pemCert, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		return c
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	if transport.TLSClientConfig.RootCAs == nil {
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	}

	transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(pemCert)
	return c
}

// ProxyFromURL calls std.ProxyFromURL to set proxy from a url.
func ProxyFromURL(url string) *Client {
	return std.ProxyFromURL(url)
}

// ProxyFromURL sets proxy from a url for the HTTP client.
func (c *Client) ProxyFromURL(url string) *Client {
	proxyURL, err := urlpkg.Parse(url)
	if err != nil {
		return c
	}

	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	transport.Proxy = http.ProxyURL(proxyURL)
	return c
}

// DisableProxyFromEnvironment calls std.DisableProxyFromEnvironment to disable proxy from environment.
func DisableProxyFromEnvironment() *Client {
	return std.DisableProxyFromEnvironment()
}

// DisableProxyFromEnvironment disables proxy form environment for HTTP client.
func (c *Client) DisableProxyFromEnvironment() *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	transport.Proxy = nil
	return c
}

// DisableSession calls std.DisableSession to disable session.
func DisableSession() *Client {
	return std.DisableSession()
}

// DisableSession disables session for the HTTP client.
func (c *Client) DisableSession() *Client {
	return c.WithCookieJar(nil)
}

// DisableRedirect calls std.DisableRedirect to disable request redirect.
func DisableRedirect() *Client {
	return std.DisableRedirect()
}

// DisableRedirect disables request redirect for the HTTP client.
func (c *Client) DisableRedirect() *Client {
	c.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}

// DisableKeepAlives calls std.DisableKeepAlives to disable Keep-Alive.
func DisableKeepAlives() *Client {
	return std.DisableKeepAlives()
}

// DisableKeepAlives disables Keep-Alive for the HTTP client.
func (c *Client) DisableKeepAlives() *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	transport.DisableKeepAlives = true
	return c
}

// InsecureSkipVerify calls std.InsecureSkipVerify to skip verify insecure certificates.
func InsecureSkipVerify() *Client {
	return std.InsecureSkipVerify()
}

// InsecureSkipVerify skips verify insecure certificates for the HTTP client.
func (c *Client) InsecureSkipVerify() *Client {
	transport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		return c
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	return c
}

// AcquireLock calls std.AcquireLock to lock std.
func AcquireLock() *Client {
	return std.AcquireLock()
}

// AcquireLock locks c.
// Use grequests across goroutines you must call AcquireLock for each request in the beginning
// otherwise would cause data race.
func (c *Client) AcquireLock() *Client {
	c.mux.Lock()
	c.withLock = true
	return c
}

// Get calls std.Get for GET HTTP request.
func Get(url string) *Client {
	return std.Get(url)
}

// Get does GET HTTP request.
func (c *Client) Get(url string) *Client {
	c.method = MethodGet
	c.url = url
	return c
}

// Head calls std.Head for HEAD HTTP request.
func Head(url string) *Client {
	return std.Head(url)
}

// Head does HEAD HTTP request.
func (c *Client) Head(url string) *Client {
	c.method = MethodHead
	c.url = url
	return c
}

// Post calls std.Post for POST HTTP request.
func Post(url string) *Client {
	return std.Post(url)
}

// Post does POST HTTP request.
func (c *Client) Post(url string) *Client {
	c.method = MethodPost
	c.url = url
	return c
}

// Put calls std.Put for PUT HTTP request.
func Put(url string) *Client {
	return std.Put(url)
}

// Put does PUT HTTP request.
func (c *Client) Put(url string) *Client {
	c.method = MethodPut
	c.url = url
	return c
}

// Patch calls std.Patch for PATCH HTTP request.
func Patch(url string) *Client {
	return std.Patch(url)
}

// Patch does PATCH HTTP request.
func (c *Client) Patch(url string) *Client {
	c.method = MethodPatch
	c.url = url
	return c
}

// DELETE calls std.Delete for DELETE HTTP request.
func Delete(url string) *Client {
	return std.Delete(url)
}

// Delete does DELETE HTTP request.
func (c *Client) Delete(url string) *Client {
	c.method = MethodDelete
	c.url = url
	return c
}

// Connect calls std.Connect CONNECT HTTP request.
func Connect(url string) *Client {
	return std.Connect(url)
}

// Connect does CONNECT HTTP request.
func (c *Client) Connect(url string) *Client {
	c.method = MethodConnect
	c.url = url
	return c
}

// Options calls std.Options for OPTIONS HTTP request.
func Options(url string) *Client {
	return std.Options(url)
}

// Options does OPTIONS HTTP request.
func (c *Client) Options(url string) *Client {
	c.method = MethodOptions
	c.url = url
	return c
}

// Trace calls std.Trace for TRACE HTTP request.
func Trace(url string) *Client {
	return std.Trace(url)
}

// Trace does TRACE HTTP request.
func (c *Client) Trace(url string) *Client {
	c.method = MethodTrace
	c.url = url
	return c
}

// Reset calls std.Reset to reset the client state.
func Reset() {
	std.Reset()
}

// Reset reset the client state so that other requests can acquire lock.
func (c *Client) Reset() {
	c.method = ""
	c.url = ""
	c.params = make(Value)
	c.form = make(Value)
	c.json = make(Data)
	c.headers = make(Value)
	c.cookies = nil
	c.files = nil

	if c.withLock {
		c.mux.Unlock()
	}
}

// Params calls std.Params to set query params.
func Params(params Value) *Client {
	return std.Params(params)
}

// Params sets query params for the HTTP request.
func (c *Client) Params(params Value) *Client {
	for k, v := range params {
		c.params.Set(k, v)
	}
	return c
}

// Form calls std.Form to send form-data.
func Form(form Value) *Client {
	return std.Form(form)
}

// Form encodes form-data into the HTTP request body.
func (c *Client) Form(form Value) *Client {
	c.headers.Set(ContentType, TypeForm)
	for k, v := range form {
		c.form.Set(k, v)
	}
	return c
}

// JSON calls std.JSON to send JSON.
func JSON(data Data) *Client {
	return std.JSON(data)
}

// JSON encodes JSON into the HTTP request body.
func (c *Client) JSON(data Data) *Client {
	c.headers.Set(ContentType, TypeJSON)
	for k, v := range data {
		c.json.Set(k, v)
	}
	return c
}

// Files calls std.Files to send multipart-data.
func Files(files ...*File) *Client {
	return std.Files(files...)
}

// Files encodes multipart-data into the HTTP request body.
func (c *Client) Files(files ...*File) *Client {
	c.files = append(c.files, files...)
	return c
}

// Headers calls std.Headers to set headers.
func Headers(headers Value) *Client {
	return std.Headers(headers)
}

// Headers sets headers for the HTTP request.
func (c *Client) Headers(headers Value) *Client {
	for k, v := range headers {
		c.headers.Set(k, v)
	}
	return c
}

// Cookies calls std.Cookies to set cookies.
func Cookies(cookies ...*http.Cookie) *Client {
	return std.Cookies(cookies...)
}

// Cookies sets cookies for the HTTP request.
func (c *Client) Cookies(cookies ...*http.Cookie) *Client {
	c.cookies = append(c.cookies, cookies...)
	return c
}

// BasicAuth calls std.BasicAuth to set basic authentication.
func BasicAuth(username, password string) *Client {
	return std.BasicAuth(username, password)
}

// BasicAuth sets basic authentication for the HTTP request.
func (c *Client) BasicAuth(username, password string) *Client {
	c.headers.Set("Authorization", "Basic "+basicAuth(username, password))
	return c
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// BearerToken calls std.BearerToken to set bearer token.
func BearerToken(token string) *Client {
	return std.BearerToken(token)
}

// BearerToken sets bearer token for the HTTP request.
func (c *Client) BearerToken(token string) *Client {
	c.headers.Set("Authorization", "Bearer "+token)
	return c
}

// Send calls std.Send to send HTTP request.
func Send() *Response {
	return std.Send()
}

// Send sends HTTP request and get its response.
func (c *Client) Send() *Response {
	resp := new(Response)
	if c.url == "" {
		resp.Err = errors.New("url not specified")
		c.Reset()
		return resp
	}
	if c.method == "" {
		resp.Err = errors.New("method not specified")
		c.Reset()
		return resp
	}

	var httpReq *http.Request
	var err error
	contentType := c.headers.Get(ContentType)
	if len(c.files) != 0 {
		httpReq, err = c.buildMultipartRequest()
	} else if strings.HasPrefix(contentType, TypeForm) {
		httpReq, err = c.buildFormRequest()
	} else if strings.HasPrefix(contentType, TypeJSON) {
		httpReq, err = c.buildJSONRequest()
	} else {
		httpReq, err = c.buildStdRequest()
	}
	if err != nil {
		resp.Err = err
		c.Reset()
		return resp
	}

	if len(c.params) != 0 {
		c.addParams(httpReq)
	}
	if len(c.headers) != 0 {
		c.addHeaders(httpReq)
	}
	if len(c.cookies) != 0 {
		c.addCookies(httpReq)
	}

	c.Reset()

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		resp.Err = err
		return resp
	}

	resp.R = httpResp
	return resp
}

func (c *Client) buildStdRequest() (*http.Request, error) {
	return http.NewRequest(c.method, c.url, nil)
}

func (c *Client) buildFormRequest() (*http.Request, error) {
	form := urlpkg.Values{}
	for k, v := range c.form {
		form.Set(k, v)
	}
	return http.NewRequest(c.method, c.url, strings.NewReader(form.Encode()))
}

func (c *Client) buildJSONRequest() (*http.Request, error) {
	b, err := json.Marshal(c.json)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(c.method, c.url, bytes.NewReader(b))
}

func (c *Client) buildMultipartRequest() (*http.Request, error) {
	r, w := io.Pipe()
	mw := multipart.NewWriter(w)
	go func() {
		defer w.Close()
		defer mw.Close()

		for i, v := range c.files {
			fieldName, fileName, filePath := v.FieldName, v.FileName, v.FilePath
			if fieldName == "" {
				fieldName = "file" + strconv.Itoa(i)
			}
			if fileName == "" {
				fileName = filepath.Base(filePath)
			}

			part, err := mw.CreateFormFile(fieldName, fileName)
			if err != nil {
				return
			}
			file, err := os.Open(filePath)
			if err != nil {
				return
			}

			io.Copy(part, file)
			file.Close()
		}
	}()

	c.headers.Set(ContentType, mw.FormDataContentType())
	return http.NewRequest(c.method, c.url, r)
}

func (c *Client) addParams(httpReq *http.Request) {
	query := httpReq.URL.Query()
	for k, v := range c.params {
		query.Set(k, v)
	}
	httpReq.URL.RawQuery = query.Encode()
}

func (c *Client) addHeaders(httpReq *http.Request) {
	for k, v := range c.headers {
		httpReq.Header.Set(k, v)
	}
}

func (c *Client) addCookies(httpReq *http.Request) {
	for _, c := range c.cookies {
		httpReq.AddCookie(c)
	}
}

// Resolve resolves response and returns the original HTTP response.
func (r *Response) Resolve() (*http.Response, error) {
	return r.R, r.Err
}

// Raw reads HTTP response and returns a []byte.
func (r *Response) Raw() ([]byte, error) {
	if r.Err != nil {
		return nil, r.Err
	}
	defer r.R.Body.Close()

	b, err := ioutil.ReadAll(r.R.Body)
	if err != nil {
		return nil, err
	}

	return b, nil
}

// Text reads HTTP response and returns a string.
func (r *Response) Text() (string, error) {
	b, err := r.Raw()
	if err != nil {
		return "", err
	}

	return string(b), nil
}

// JSON reads HTTP response and unmarshals it.
func (r *Response) JSON(v interface{}) error {
	b, err := r.Raw()
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}

// EnsureStatusOk ensures status code of the HTTP response must be 200.
func (r *Response) EnsureStatusOk() *Response {
	if r.Err != nil {
		return r
	}
	if r.R.StatusCode != http.StatusOK {
		r.Err = fmt.Errorf("status code 200 expected but got: %d", r.R.StatusCode)
	}
	return r
}

// EnsureStatus2xx ensures status code of the HTTP response must be 2xx.
func (r *Response) EnsureStatus2xx(httpResp *http.Response) *Response {
	if r.Err != nil {
		return r
	}
	if r.R.StatusCode != http.StatusOK {
		r.Err = fmt.Errorf("status code 2xx expected but got: %d", r.R.StatusCode)
	}
	return r
}
