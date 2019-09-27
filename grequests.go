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
	Ver = "0.1"

	DefaultTimeout = 120 * time.Second
	ContentType    = "Content-Type"
	TypeForm       = "application/x-www-form-urlencoded"
	TypeJSON       = "application/json"

	MethodGet     = "GET"
	MethodHead    = "HEAD"
	MethodPost    = "POST"
	MethodPut     = "PUT"
	MethodPatch   = "PATCH" // RFC 5789
	MethodDelete  = "DELETE"
	MethodConnect = "CONNECT"
	MethodOptions = "OPTIONS"
	MethodTrace   = "TRACE"
)

var std = New()

type (
	Request struct {
		client               *http.Client
		method               string
		url                  string
		params               Value
		form                 Value
		json                 Data
		headers              Value
		cookies              []*http.Cookie
		files                []*File
		reqInterceptorChain  *requestInterceptorChain
		respInterceptorChain *responseInterceptorChain
		mux                  *sync.Mutex
		withLock             bool
	}

	Response struct {
		R   *http.Response
		Err error
	}

	Value map[string]string
	Data  map[string]interface{}

	File struct {
		FieldName string
		FileName  string
		FilePath  string
	}

	RequestInterceptor  func(httpReq *http.Request) error
	ResponseInterceptor func(httpResp *http.Response) error

	requestInterceptorChain struct {
		mux          *sync.RWMutex
		interceptors []RequestInterceptor
	}

	responseInterceptorChain struct {
		mux          *sync.RWMutex
		interceptors []ResponseInterceptor
	}
)

func (v Value) Get(key string) string {
	return v[key]
}

func (v Value) Set(key string, value string) {
	v[key] = value
}

func (v Value) Del(key string) {
	delete(v, key)
}

func (d Data) Get(key string) interface{} {
	return d[key]
}

func (d Data) Set(key string, value interface{}) {
	d[key] = value
}

func (d Data) Del(key string) {
	delete(d, key)
}

func New() *Request {
	req := &Request{
		client:  http.DefaultClient,
		params:  make(Value),
		form:    make(Value),
		json:    make(Data),
		headers: make(Value),
		reqInterceptorChain: &requestInterceptorChain{
			mux: new(sync.RWMutex),
		},
		respInterceptorChain: &responseInterceptorChain{
			mux: new(sync.RWMutex),
		},
		mux: new(sync.Mutex),
	}

	jar, _ := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	req.client.Jar = jar
	req.client.Transport = http.DefaultTransport
	req.client.Timeout = DefaultTimeout

	req.headers.Set("User-Agent", "grequests "+Ver)
	return req
}

func WithTransport(transport http.RoundTripper) *Request {
	return std.WithTransport(transport)
}

func (req *Request) WithTransport(transport http.RoundTripper) *Request {
	req.client.Transport = transport
	return req
}

func WithRedirectPolicy(policy func(req *http.Request, via []*http.Request) error) *Request {
	return std.WithRedirectPolicy(policy)
}

func (req *Request) WithRedirectPolicy(policy func(req *http.Request, via []*http.Request) error) *Request {
	req.client.CheckRedirect = policy
	return req
}

func WithCookieJar(jar http.CookieJar) *Request {
	return std.WithCookieJar(jar)
}

func (req *Request) WithCookieJar(jar http.CookieJar) *Request {
	req.client.Jar = jar
	return req
}

func WithTimeout(timeout time.Duration) *Request {
	return std.WithTimeout(timeout)
}

func (req *Request) WithTimeout(timeout time.Duration) *Request {
	req.client.Timeout = timeout
	return req
}

func WithClientCertificates(certs ...tls.Certificate) *Request {
	return std.WithClientCertificates(certs...)
}

func (req *Request) WithClientCertificates(certs ...tls.Certificate) *Request {
	transport, ok := req.client.Transport.(*http.Transport)
	if !ok {
		return req
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}

	transport.TLSClientConfig.Certificates = append(transport.TLSClientConfig.Certificates, certs...)
	return req
}

func WithRootCAs(pemFilePath string) *Request {
	return std.WithRootCAs(pemFilePath)
}

func (req *Request) WithRootCAs(pemFilePath string) *Request {
	pemCert, err := ioutil.ReadFile(pemFilePath)
	if err != nil {
		return req
	}

	transport, ok := req.client.Transport.(*http.Transport)
	if !ok {
		return req
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	if transport.TLSClientConfig.RootCAs == nil {
		transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	}

	transport.TLSClientConfig.RootCAs.AppendCertsFromPEM(pemCert)
	return req
}

func WithRequestInterceptorChain(interceptors ...RequestInterceptor) *Request {
	return std.WithRequestInterceptorChain(interceptors...)
}

func (req *Request) WithRequestInterceptorChain(interceptors ...RequestInterceptor) *Request {
	req.reqInterceptorChain.interceptors = append(req.reqInterceptorChain.interceptors, interceptors...)
	return req
}

func WithResponseInterceptorChain(interceptors ...ResponseInterceptor) *Request {
	return std.WithResponseInterceptorChain(interceptors...)
}

func (req *Request) WithResponseInterceptorChain(interceptors ...ResponseInterceptor) *Request {
	req.respInterceptorChain.interceptors = append(req.respInterceptorChain.interceptors, interceptors...)
	return req
}

func ProxyFromURL(url string) *Request {
	return std.ProxyFromURL(url)
}

func (req *Request) ProxyFromURL(url string) *Request {
	proxyURL, err := urlpkg.Parse(url)
	if err != nil {
		return req
	}

	transport, ok := req.client.Transport.(*http.Transport)
	if !ok {
		return req
	}

	transport.Proxy = http.ProxyURL(proxyURL)
	return req
}

func DisableProxyFromEnvironment() *Request {
	return std.DisableProxyFromEnvironment()
}

func (req *Request) DisableProxyFromEnvironment() *Request {
	transport, ok := req.client.Transport.(*http.Transport)
	if !ok {
		return req
	}

	transport.Proxy = nil
	return req
}

func DisableSession() *Request {
	return std.DisableSession()
}

func (req *Request) DisableSession() *Request {
	return req.WithCookieJar(nil)
}

func DisableRedirect() *Request {
	return std.DisableRedirect()
}

func (req *Request) DisableRedirect() *Request {
	req.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return req
}

func DisableKeepAlives() *Request {
	return std.DisableKeepAlives()
}

func (req *Request) DisableKeepAlives() *Request {
	transport, ok := req.client.Transport.(*http.Transport)
	if !ok {
		return req
	}

	transport.DisableKeepAlives = true
	return req
}

func InsecureSkipVerify() *Request {
	return std.InsecureSkipVerify()
}

func (req *Request) InsecureSkipVerify() *Request {
	transport, ok := req.client.Transport.(*http.Transport)
	if !ok {
		return req
	}

	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	transport.TLSClientConfig.InsecureSkipVerify = true
	return req
}

func AcquireLock() *Request {
	return std.AcquireLock()
}

func (req *Request) AcquireLock() *Request {
	req.mux.Lock()
	req.withLock = true
	return req
}

func Get(url string) *Request {
	return std.Get(url)
}

func (req *Request) Get(url string) *Request {
	req.method = MethodGet
	req.url = url
	return req
}

func Head(url string) *Request {
	return std.Head(url)
}

func (req *Request) Head(url string) *Request {
	req.method = MethodHead
	req.url = url
	return req
}

func Post(url string) *Request {
	return std.Post(url)
}

func (req *Request) Post(url string) *Request {
	req.method = MethodPost
	req.url = url
	return req
}

func Put(url string) *Request {
	return std.Put(url)
}

func (req *Request) Put(url string) *Request {
	req.method = MethodPut
	req.url = url
	return req
}

func Patch(url string) *Request {
	return std.Get(url)
}

func (req *Request) Patch(url string) *Request {
	req.method = MethodPatch
	req.url = url
	return req
}

func Delete(url string) *Request {
	return std.Delete(url)
}

func (req *Request) Delete(url string) *Request {
	req.method = MethodDelete
	req.url = url
	return req
}

func Connect(url string) *Request {
	return std.Connect(url)
}

func (req *Request) Connect(url string) *Request {
	req.method = MethodConnect
	req.url = url
	return req
}

func Options(url string) *Request {
	return std.Options(url)
}

func (req *Request) Options(url string) *Request {
	req.method = MethodOptions
	req.url = url
	return req
}

func Trace(url string) *Request {
	return std.Trace(url)
}

func (req *Request) Trace(url string) *Request {
	req.method = MethodTrace
	req.url = url
	return req
}

func (req *Request) Reset() {
	req.method = ""
	req.url = ""
	req.params = make(Value)
	req.form = make(Value)
	req.json = make(Data)
	req.headers = make(Value)
	req.cookies = nil
	req.files = nil

	if req.withLock {
		req.mux.Unlock()
	}
}

func (req *Request) Params(params Value) *Request {
	for k, v := range params {
		req.params.Set(k, v)
	}
	return req
}

func (req *Request) Form(form Value) *Request {
	req.headers.Set(ContentType, TypeForm)
	for k, v := range form {
		req.form.Set(k, v)
	}
	return req
}

func (req *Request) JSON(data Data) *Request {
	req.headers.Set(ContentType, TypeJSON)
	for k, v := range data {
		req.json.Set(k, v)
	}
	return req
}

func (req *Request) Files(files ...*File) *Request {
	req.files = append(req.files, files...)
	return req
}

func (req *Request) Headers(headers Value) *Request {
	for k, v := range headers {
		req.headers.Set(k, v)
	}
	return req
}

func (req *Request) Cookies(cookies ...*http.Cookie) *Request {
	req.cookies = append(req.cookies, cookies...)
	return req
}

func (req *Request) BasicAuth(username, password string) *Request {
	req.headers.Set("Authorization", "Basic "+basicAuth(username, password))
	return req
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

func (req *Request) BearerToken(token string) *Request {
	req.headers.Set("Authorization", "Bearer "+token)
	return req
}

func (req *Request) Send() *Response {
	result := new(Response)
	if req.url == "" {
		result.Err = errors.New("url not specified")
		req.Reset()
		return result
	}

	var httpReq *http.Request
	var err error
	contentType := req.headers.Get(ContentType)
	if len(req.files) != 0 {
		httpReq, err = req.buildMultipartRequest()
	} else if strings.HasPrefix(contentType, TypeForm) {
		httpReq, err = req.buildFormRequest()
	} else if strings.HasPrefix(contentType, TypeJSON) {
		httpReq, err = req.buildJSONRequest()
	} else {
		httpReq, err = req.buildStdRequest()
	}
	if err != nil {
		result.Err = err
		req.Reset()
		return result
	}

	if len(req.params) != 0 {
		req.addParams(httpReq)
	}
	if len(req.headers) != 0 {
		req.addHeaders(httpReq)
	}
	if len(req.cookies) != 0 {
		req.addCookies(httpReq)
	}

	req.Reset()

	// 请求拦截器
	if len(req.reqInterceptorChain.interceptors) != 0 {
		req.reqInterceptorChain.mux.RLock()
		defer req.reqInterceptorChain.mux.RUnlock()
		for _, interceptor := range req.reqInterceptorChain.interceptors {
			err = interceptor(httpReq)
			if err != nil {
				result.Err = err
				return result
			}
		}
	}

	httpResp, err := req.client.Do(httpReq)
	if err != nil {
		result.Err = err
		return result
	}

	// 响应拦截器
	if len(req.respInterceptorChain.interceptors) != 0 {
		req.respInterceptorChain.mux.RLock()
		defer req.respInterceptorChain.mux.RUnlock()
		for _, interceptor := range req.respInterceptorChain.interceptors {
			err = interceptor(httpResp)
			if err != nil {
				result.Err = err
				return result
			}
		}
	}

	result.R = httpResp
	return result
}

func (req *Request) buildStdRequest() (*http.Request, error) {
	return http.NewRequest(req.method, req.url, nil)
}

func (req *Request) buildFormRequest() (*http.Request, error) {
	form := urlpkg.Values{}
	for k, v := range req.form {
		form.Set(k, v)
	}
	return http.NewRequest(req.method, req.url, strings.NewReader(form.Encode()))
}

func (req *Request) buildJSONRequest() (*http.Request, error) {
	b, err := json.Marshal(req.json)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(req.method, req.url, bytes.NewReader(b))
}

func (req *Request) buildMultipartRequest() (*http.Request, error) {
	r, w := io.Pipe()
	mw := multipart.NewWriter(w)
	go func() {
		defer w.Close()
		defer mw.Close()

		for i, v := range req.files {
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

	req.headers.Set(ContentType, mw.FormDataContentType())
	return http.NewRequest(req.method, req.url, r)
}

func (req *Request) addParams(httpReq *http.Request) {
	query := httpReq.URL.Query()
	for k, v := range req.params {
		query.Set(k, v)
	}
	httpReq.URL.RawQuery = query.Encode()
}

func (req *Request) addHeaders(httpReq *http.Request) {
	for k, v := range req.headers {
		httpReq.Header.Set(k, v)
	}
}

func (req *Request) addCookies(httpReq *http.Request) {
	for _, c := range req.cookies {
		httpReq.AddCookie(c)
	}
}

func (resp *Response) Resolve() (*http.Response, error) {
	return resp.R, resp.Err
}

func (resp *Response) Raw() ([]byte, error) {
	if resp.Err != nil {
		return nil, resp.Err
	}
	defer resp.R.Body.Close()

	b, err := ioutil.ReadAll(resp.R.Body)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (resp *Response) Text() (string, error) {
	b, err := resp.Raw()
	if err != nil {
		return "", err
	}

	return string(b), nil
}

func (resp *Response) JSON(v interface{}) error {
	b, err := resp.Raw()
	if err != nil {
		return err
	}

	return json.Unmarshal(b, v)
}

func EnsureStatusOk(httpResp *http.Response) (err error) {
	if httpResp.StatusCode != http.StatusOK {
		err = fmt.Errorf("status code 200 expected but got: %d", httpResp.StatusCode)
	}
	return
}

func EnsureStatus2xx(httpResp *http.Response) (err error) {
	if httpResp.StatusCode/100 != 2 {
		err = fmt.Errorf("status code 2xx expected but got: %d", httpResp.StatusCode)
	}
	return
}
