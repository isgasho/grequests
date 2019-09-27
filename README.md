# grequests 
A simple and user-friendly HTTP request library for Go, inspired by the well-known Python project [requests](https://github.com/psf/requests).

[![Build Status](https://travis-ci.org/winterssy/grequests.svg?branch=master)](https://travis-ci.org/winterssy/grequests) [![Go Report Card](https://goreportcard.com/badge/winterssy/grequests)](https://goreportcard.com/report/winterssy/grequests) [![GoDoc](https://godoc.org/github.com/winterssy/grequests?status.svg)](https://godoc.org/github.com/winterssy/grequests) [![License](https://img.shields.io/github/license/winterssy/grequests.svg)](LICENSE)

## Features

- GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, etc.
- Easy set query params, headers and cookies.
- Easy encode form-data or JSON into the request body.
- Easy upload one or more file(s).
- Easy set basic authentication or bearer token.
- Easy customize root certificates and client certificates.
- Easy set proxy.
- Automatic cookie management.
- Customize HTTP client, transport, redirect policy, cookie jar and timeout.
- Responses can be easily serialized into JSON, string or bytes.
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
        "msg": "hello world",
        "num": 2019,
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
            FieldName: "testimage1",
            FileName:  "testimage1.jpg",
            FilePath:  "./testdata/testimage1.jpg",
        },
        &grequests.File{
            FieldName: "testimage2",
            FileName:  "testimage2.jpg",
            FilePath:  "./testdata/testimage2.jpg",
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
data, err := grequests.Get("http://httpbin.org/basic-auth/admin/pass").
    BasicAuth("admin", "pass").
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

### Concurrent Safe

```go
const MaxWorker = 1000
wg := new(sync.WaitGroup)

for i := 0; i < MaxWorker; i += 1 {
    wg.Add(1)
    go func(i int) {
        defer wg.Done()

        params := grequests.Value{}
        params.Set(fmt.Sprintf("key%d", i), fmt.Sprintf("value%d", i))

        data, err := grequests.AcquireLock().Get("http://httpbin.org/get").
            Params(params).
            Send().
            Text()
        if err != nil {
            return
        }

        fmt.Println(data)
    }(i)
}

wg.Wait()
```

## License

MIT.

## Thanks

- [xuanbo/requests](https://github.com/xuanbo/requests)
- [ddliu/go-httpclient](https://github.com/ddliu/go-httpclient)
- [go-resty/resty](https://github.com/go-resty/resty)
