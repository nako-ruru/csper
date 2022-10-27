package main

import (
	"fmt"
	"io"
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
		defer func() {
			_ = req.Body.Close()
		}()
		body, err := io.ReadAll(req.Body)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)
			return
		}
		log.Printf(string(body))
	}
	return reportToHandler
}
