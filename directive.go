package main

type FetchDirective struct {
	Type                string //script, style etc
	FetchDirectiveItems []FetchDirectiveItem
}

type FetchDirectiveItem struct {
	Type  string //nonce, sha256 etc
	Value string
}
