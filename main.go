package main

import (
	"compress/gzip"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/nako-ruru/httpcompression"
	"github.com/nako-ruru/httpcompression/contrib/andybalholm/brotli"
	"github.com/nako-ruru/httpcompression/contrib/compress/zlib"
	"gopkg.in/yaml.v3"
	"net/http"
	"os"
)

func main() {
	yamlFile, err := os.ReadFile("./application.yml")
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

	mux := http.NewServeMux()

	var reportUris = ReportUris(config)
	reportToHandler := NewReport()
	for _, uri := range reportUris {
		mux.HandleFunc(uri.(string), reportToHandler)
	}

	// initialize a reverse proxy and pass the actual backend server url here
	proxy, err := NewProxy(config)
	if err != nil {
		panic(err)
	}
	// handle all requests to your server using the proxy
	mux.Handle("/", proxy)

	compressionHandler, err := compressionHandler(mux)
	if err != nil {
		panic(err)
	}
	http.Handle("/", compressionHandler)

	err = http.ListenAndServe(formatAddress(config.Listen), nil)
	if err != nil {
		panic(err)
	}
}

func compressionHandler(handler http.Handler) (http.Handler, error) {
	c, err := brotli.New(brotli.Options{Quality: brotli.DefaultCompression, LGWin: 16})
	if err != nil {
		return nil, err
	}
	contentTypes := []string{
		"application/json",
		"application/javascript",
		"text/javascript",
		"text/css",
		"text/html",
		"text/plain",
	}
	opts := []httpcompression.Option{
		httpcompression.DeflateCompressionLevel(zlib.DefaultCompression),
		httpcompression.GzipCompressionLevel(gzip.DefaultCompression),
		httpcompression.BrotliCompressor(c),
		httpcompression.MinSize(1024),
		httpcompression.ContentTypes(contentTypes, false),
	}
	adapter, err := httpcompression.Adapter(opts...)
	if err != nil {
		return nil, err
	}
	return adapter(handler), nil
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
