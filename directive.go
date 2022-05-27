package main

type FetchDirective struct {
	 Type string
	 InlineSources []InlineSource
}

type InlineSource struct {
	Type string
	Value string
}