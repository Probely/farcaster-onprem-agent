package check

import (
	"net/http"
	"net/http/httputil"
	"time"
)

var client = &http.Client{
	Timeout: time.Second * 20,
}

type HTTPResult struct {
	StatusCode int
	Data       []byte
}

func HTTPEndpoint(url string) (*HTTPResult, error) {
	var err error
	if _, err = http.NewRequest("GET", url, nil); err != nil {
		return nil, err
	}

	var resp *http.Response
	if resp, err = client.Get(url); err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	res := &HTTPResult{StatusCode: resp.StatusCode}
	res.Data, err = httputil.DumpResponse(resp, true)

	return res, err
}
