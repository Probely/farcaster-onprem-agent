package check

import (
	"net/http"
	"time"
)

var client = &http.Client{
	Timeout: time.Second * 20,
}

func HTTPEndpoint(url string) error {
	var err error
	if _, err = http.NewRequest("GET", url, nil); err != nil {
		return err
	}
	_, err = client.Get(url)

	return err
}
