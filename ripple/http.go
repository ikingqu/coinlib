package ripple

import (
	"time"

	"github.com/go-resty/resty"
	"github.com/maiiz/coinlib/log"
)

func init() {
	resty.
		SetRetryCount(30).
		SetTimeout(30 * time.Second)
	//SetRetryWaitTime(3 * time.Second).
	//SetRetryMaxWaitTime(30 * time.Second).
}

func Call(req, url string) ([]byte, error) {
	resp, err := resty.R().
		SetHeader("Content-Type", "application/json").
		SetBody([]byte(req)).
		Post(url)
	if err != nil {
		log.Errorf("request error %+v", err)
	}
	return resp.Body(), err
}
