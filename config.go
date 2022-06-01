package main

type Config struct {
	Listen                string                `yaml:"listen"`
	Backend               string                `yaml:"backend"`
	ContentSecurityPolicy ContentSecurityPolicy `yaml:"content-security-policy"`
	ReportTo              string                `yaml:"report-to"`
	ReportUris            interface{}           `yaml:"report-uris"`
}
type ContentSecurityPolicy struct {
	Pattern         string   `yaml:"pattern"`
	InlineScriptSrc string   `yaml:"inline-script-src"`
	InlineStyleSrc  string   `yaml:"inline-style-src"`
	InlineTypes     []string `yaml:"inline-types"`
}
