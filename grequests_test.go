package grequests_test

import (
	"github.com/winterssy/grequests"
	"net/http"
	"testing"
)

func TestGet(t *testing.T) {
	resp := grequests.Get("http://httpbin.org/get").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestHead(t *testing.T) {
	resp := grequests.Head("http://httpbin.org").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestPost(t *testing.T) {
	resp := grequests.Post("http://httpbin.org/post").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestPut(t *testing.T) {
	resp := grequests.Put("http://httpbin.org/put").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestPatch(t *testing.T) {
	resp := grequests.Patch("http://httpbin.org/patch").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestDelete(t *testing.T) {
	resp := grequests.Delete("http://httpbin.org/delete").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestOptions(t *testing.T) {
	resp := grequests.Options("http://httpbin.org").Send().EnsureStatusOk()
	if resp.Err != nil {
		t.Error(resp.Err)
	}
}

func TestRequest_Params(t *testing.T) {
	var data struct {
		Args map[string]string `json:"args"`
	}
	err := grequests.Get("http://httpbin.org/get").
		Params(
			grequests.Value{
				"key1": "value1",
				"key2": "value2",
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Args["key1"] != "value1" || data.Args["key2"] != "value2" {
		t.Error("Set params failed")
	}
}

func TestRequest_Form(t *testing.T) {
	var data struct {
		Form map[string]string `json:"form"`
	}
	err := grequests.Post("http://httpbin.org/post").
		Form(
			grequests.Value{
				"key1": "value1",
				"key2": "value2",
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Form["key1"] != "value1" || data.Form["key2"] != "value2" {
		t.Error("Send form failed")
	}
}

func TestRequest_JSON(t *testing.T) {
	var data struct {
		JSON struct {
			Msg string `json:"msg"`
			Num int    `json:"num"`
		} `json:"json"`
	}
	err := grequests.Post("http://httpbin.org/post").
		JSON(
			grequests.Data{
				"msg": "hello world",
				"num": 2019,
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.JSON.Msg != "hello world" || data.JSON.Num != 2019 {
		t.Error("Send json failed")
	}
}

func TestRequest_Headers(t *testing.T) {
	var data struct {
		Headers map[string]string `json:"headers"`
	}
	err := grequests.Get("http://httpbin.org/get").
		Headers(
			grequests.Value{
				"Origin":  "http://httpbin.org",
				"Referer": "http://httpbin.org",
			}).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Headers["Origin"] != "http://httpbin.org" || data.Headers["Referer"] != "http://httpbin.org" {
		t.Error("Set headers failed")
	}
}

func TestRequest_Cookies(t *testing.T) {
	var data struct {
		Cookies map[string]string `json:"cookies"`
	}
	err := grequests.Get("http://httpbin.org/cookies/set").
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
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if data.Cookies["name1"] != "value1" || data.Cookies["name2"] != "value2" {
		t.Error("Set cookies failed")
	}
}

func TestRequest_Files(t *testing.T) {
	var data struct {
		Files map[string]string `json:"files"`
	}
	err := grequests.Post("http://httpbin.org/post").
		Files(
			&grequests.File{
				FieldName: "testfile1",
				FileName:  "testfile1.txt",
				FilePath:  "./testdata/testfile1.txt",
			},
			&grequests.File{
				FieldName: "testfile2",
				FileName:  "testfile2.txt",
				FilePath:  "./testdata/testfile2.txt",
			},
		).
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}

	if data.Files["testfile1"] == "" || data.Files["testfile2"] == "" {
		t.Error("Send files failed")
	}
}

func TestRequest_BasicAuth(t *testing.T) {
	var data struct {
		Authenticated bool   `json:"authenticated"`
		User          string `json:"user"`
	}
	err := grequests.Get("http://httpbin.org/basic-auth/admin/pass").
		BasicAuth("admin", "pass").
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if !data.Authenticated || data.User != "admin" {
		t.Error("Set basic authentication failed")
	}
}

func TestRequest_BearerToken(t *testing.T) {
	var data struct {
		Authenticated bool   `json:"authenticated"`
		Token         string `json:"token"`
	}
	err := grequests.Get("http://httpbin.org/bearer").
		BearerToken("grequests").
		Send().
		EnsureStatusOk().
		JSON(&data)
	if err != nil {
		t.Error(err)
	}
	if !data.Authenticated || data.Token != "grequests" {
		t.Error("Set basic authentication failed")
	}
}
