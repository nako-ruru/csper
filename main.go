package main

import (
	"fmt"
	"github.com/dlclark/regexp2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"net/http"
	"path/filepath"
)

func main() {
	filename, err := filepath.Abs("./application.yml")
	if err != nil {
		panic(err)
	}
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}

	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		panic(err)
	}

	for _, inlineType := range config.ContentSecurityPolicy.InlineTypes {
		if NewGenerator(inlineType) == nil {
			panic(fmt.Errorf(`unknown generator "%s"`, inlineType))
		}
	}

	var reportUris = ReportUris(config)
	reportToHandler := NewReport()
	for _, uri := range reportUris {
		http.HandleFunc(uri.(string), reportToHandler)
	}

	// initialize a reverse proxy and pass the actual backend server url here
	proxy, err := NewProxy(config)
	if err != nil {
		panic(err)
	}
	// handle all requests to your server using the proxy
	http.Handle("/", proxy)

	log.Fatal(http.ListenAndServe(formatAddress(config.Listen), nil))
}

func formatAddress(address string) string {
	regex := regexp2.MustCompile(`^\d+$`, regexp2.None)
	matched, err := regex.MatchString(address)
	if err != nil {
		panic(err)
	}
	if matched {
		return ":" + address
	}
	return address
}
