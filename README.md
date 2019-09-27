# grequests 
A simple and user-friendly HTTP request library for Go, inspired by the well-known Python project [requests](https://github.com/psf/requests).

[![Build Status](https://travis-ci.org/go-resty/resty.svg?branch=master)](https://travis-ci.org/go-resty/resty) [![Go Report Card](https://goreportcard.com/badge/go-resty/resty)](https://goreportcard.com/report/go-resty/resty) [![GoDoc](https://godoc.org/github.com/go-resty/resty?status.svg)](https://godoc.org/github.com/go-resty/resty) [![License](https://img.shields.io/github/license/go-resty/resty.svg)](LICENSE)

## Features

- Support for all HTTP verbs. GET, HEAD, POST, PUT, PATCH, DELETE, CONNECT, OPTIONS, TRACE.
- Easy set query params, headers and cookies.
- Easy encode a form-data or JSON into the request body.
- Easy upload one or more file(s).
- Easy set basic authentication or bearer token.
- Easy customize root certificates and client certificates.
- Easy set proxy.
- Easy play with session.
- Customize HTTP client. Transport, redirect policy, cookie jar and timeout.
- Support request and response interceptor.
- Responses can be easily serialized into JSON, sting or bytes.
- Concurrent safe.

## Install

```sh
go get -u github.com/winterssy/grequests
```

## Usage

```go
import "github.com/winterssy/grequests"
```

## Examples

- [Set Params](#Set-Params)
- [Set Headers](#Set-Headers)
- [Set Cookies](#Set-Cookies)
- [Send Form](#Send-Form)
- [Send JSON](#Send-JSON)
- [Send Files](#Send-Files)
- [Set Basic Authentication](#Set-Basic-Authentication)
- [Set Bearer Token](#Set-Bearer-Token)
- [Customize HTTP Client](#Customize-HTTP-Client)
- [Set Proxy](#Set-Proxy)
- [Use Response Interceptors](#Use-Response-Interceptors)
- [Concurrent Safe](#Concurrent-Safe)

### Set Params

```go
data, err := grequests.Get("http://httpbin.org/get").
    Params(grequests.Value{
        "key1": "value1",
        "key2": "value2",
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Headers

```go
data, err := grequests.Get("http://httpbin.org/get").
    Headers(grequests.Value{
        "Origin":  "http://httpbin.org",
        "Referer": "http://httpbin.org",
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Cookies

```go
data, err := grequests.Get("http://httpbin.org/cookies/set").
    Cookies(
        &http.Cookie{
            Name:  "name1",
            Value: "value1",
        },
        &http.Cookie{
            Name:  "name2",
            Value: "value2",
        },
    ).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Send Form

```go
data, err := grequests.Post("http://httpbin.org/post").
    Form(grequests.Value{
        "key1": "value1",
        "key2": "value2",
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Send JSON

```go
data, err := grequests.Post("http://httpbin.org/post").
    JSON(grequests.Data{
        "key1": "value1",
        "key2": []interface{}{"v", "a", "l", "u", "e", 2},
    }).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Send Files

```go
data, err := grequests.Post("http://httpbin.org/post").
    Files(
        &grequests.File{
            FieldName: "image1",
            FileName:  "image1.jpg",
            FilePath:  "./testdata/image1.jpg",
        },
        &grequests.File{
            FieldName: "image2",
            FileName:  "image2.jpg",
            FilePath:  "./testdata/image2.jpg",
        },
    ).
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Basic Authentication

```go
data, err := grequests.Get("http://httpbin.org/basic-auth/user/pass").
    BasicAuth("user", "pass").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Bearer Token

```go
data, err := grequests.Get("http://httpbin.org/bearer").
    BearerToken("grequests").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Customize HTTP Client

```go
transport := &http.Transport{
    Proxy: http.ProxyFromEnvironment,
    DialContext: (&net.Dialer{
        Timeout:   30 * time.Second,
        KeepAlive: 30 * time.Second,
    }).DialContext,
    ForceAttemptHTTP2:     true,
    MaxIdleConns:          100,
    IdleConnTimeout:       90 * time.Second,
    TLSHandshakeTimeout:   10 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
}
redirectPolicy := func(req *http.Request, via []*http.Request) error {
    return http.ErrUseLastResponse
}
jar, _ := cookiejar.New(&cookiejar.Options{
    PublicSuffixList: publicsuffix.List,
})
timeout := 60 * time.Second

req := grequests.WithTransport(transport).
    WithRedirectPolicy(redirectPolicy).
    WithCookieJar(jar).
    WithTimeout(timeout)

data, err := req.Get("http://httpbin.org/get").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Set Proxy

```go
data, err := grequests.ProxyFromURL("http://127.0.0.1:1081").
    Get("http://httpbin.org/get").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Use Response Interceptors

```go
data, err := grequests.WithResponseInterceptorChain(grequests.EnsureStatusOk).
    Get("http://httpbin.org/get").
    Send().
    Text()
if err != nil {
    panic(err)
}
fmt.Println(data)
```

### Concurrent Safe

```go
wg := new(sync.WaitGroup)

wg.Add(1)
go func() {
    defer wg.Done()
    data, err := grequests.AcquireLock().Get("http://httpbin.org/get").
        Params(grequests.Value{
            "key1": "value1",
            "key2": "value2",
        }).
        Send().
        Text()
    if err != nil {
        return
    }
    fmt.Println(data)
}()

wg.Add(1)
go func() {
    defer wg.Done()
    data, err := grequests.AcquireLock().Get("http://httpbin.org/get").
    Params(grequests.Value{
        "key3": "value3",
        "key4": "value4",
    }).
    Send().
    Text()
    if err != nil {
        return
    }
    fmt.Println(data)
}()

wg.Wait()
```

## License

MIT.

## Thanks

- [xuanbo/requests](https://github.com/xuanbo/requests)
- [ddliu/go-httpclient](https://github.com/ddliu/go-httpclient)
- [go-resty/resty](https://github.com/go-resty/resty)
