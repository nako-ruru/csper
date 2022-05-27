package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
)

func ReportUris(config Config) []interface{} {
	switch config.ReportUris.(type) {
	case string:
		return []interface{}{config.ReportUris}
	case []interface{}:
		return config.ReportUris.([]interface{})
	default:
		panic(fmt.Errorf("unsupported report-uris: %v", config.ReportUris))
	}
}

func NewReport() func(http.ResponseWriter, *http.Request) {
	reportToHandler := func(rw http.ResponseWriter, req *http.Request) {
		defer func(body io.ReadCloser) {
			_ = body.Close()
		}(req.Body)
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			rw.WriteHeader(502)
			return
		}
		log.Printf(string(body))
	}
	return reportToHandler
}
