package actions

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"time"
)

var httpClient = &http.Client{
	Timeout: time.Second * 20,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

type HTTPResult struct {
	StatusCode int
	Data       []byte
}

func CheckHTTPEndpoint(url string) (*HTTPResult, error) {
	var err error
	if _, err = http.NewRequest("GET", url, nil); err != nil {
		return nil, err
	}

	var resp *http.Response
	if resp, err = httpClient.Get(url); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	res := &HTTPResult{StatusCode: resp.StatusCode}
	res.Data, err = httputil.DumpResponse(resp, true)
	if err == nil && (res.StatusCode < 200 || res.StatusCode >= 400) {
		msg := fmt.Sprint("Unexpected HTTP status code: ", res.StatusCode)
		err = errors.New(msg)
	}
	return res, err
}
