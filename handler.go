package main

import (
	"bytes"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/jaevor/go-nanoid"
	"github.com/relengxing/go-multimap"
	"github.com/relengxing/go-multimap/setmultimap"
	"github.com/zyedidia/generic"
	"github.com/zyedidia/generic/hashset"
	"html"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
)

type Handler struct {
	config      Config
	idGenerator func() string
	sync.RWMutex
}

func (_this *Handler) handle(resp *http.Response) (err error) {
	defer func() {
		if e := recover(); e != nil {
			var desc string
			switch e.(type) {
			case error:
				desc = e.(error).Error()
				break
			default:
				desc = fmt.Sprintf("%s", e)
			}
			err = fmt.Errorf("%s:\n%s", desc, string(stack(3)))
		}
	}()
	resp.Header.Del("Vary")
	contentType := resp.Header.Get("Content-type")
	contentTypeRegex := regexp2.MustCompile(`^text/htm`, regexp2.IgnoreCase)
	matched, unimportantErr := contentTypeRegex.MatchString(contentType)
	if unimportantErr != nil {
		log.Println(unimportantErr)
		return
	}
	if !matched {
		return
	}

	if len(_this.config.ReportTo) > 0 {
		resp.Header.Set("REPORT-TO", _this.config.ReportTo)
	}
	customDirectives := resp.Header.Get("X-CUSTOM-CSP")
	resp.Header.Del("X-CUSTOM-CSP")
	newRespBody, csp, unimportantErr := _this.proceed(resp.Body, customDirectives)
	if unimportantErr != nil {
		log.Println(unimportantErr)
	}
	resp.Body = newRespBody
	if len(strings.TrimSpace(csp)) > 0 {
		resp.Header.Set("CONTENT-SECURITY-POLICY", csp)
	}
	return
}

func (_this *Handler) proceed(respBody io.ReadCloser, customDirectives string) (newRespBody io.ReadCloser, csp string, err error) {
	defer func() {
		if e := recover(); e != nil {
			var desc string
			switch e.(type) {
			case error:
				desc = e.(error).Error()
				break
			default:
				desc = fmt.Sprintf("%s", e)
			}
			err = fmt.Errorf("%s:\n%s", desc, string(stack(3)))
		}
	}()
	newRespBody, csp = respBody, _this.config.ContentSecurityPolicy.Template
	if len(_this.config.ContentSecurityPolicy.InlineTypes) == 0 {
		return
	}

	defer func() {
		_ = respBody.Close()
	}()
	respBodyBytes, err := io.ReadAll(respBody)
	if err != nil {
		return
	}
	newRespBody = io.NopCloser(bytes.NewBuffer(respBodyBytes))

	newBody := _this.handleUITags(string(respBodyBytes))
	newBody, requiredDirectives := _this.handleDirectiveTags(newBody)
	csp, err = _this.handleHeader(customDirectives, requiredDirectives)
	newRespBody = io.NopCloser(bytes.NewBufferString(newBody))
	return
}

func (_this *Handler) handleError(writer http.ResponseWriter, _ *http.Request, err error) {
	writer.WriteHeader(502)
	_, _ = writer.Write([]byte(fmt.Sprintf("%+v", err)))
}

// NewProxy takes target host and creates a reverse proxy
func NewProxy(config Config) (*httputil.ReverseProxy, error) {
	u, err := url.Parse(config.Backend)
	if err != nil {
		return nil, err
	}

	proxy := httputil.NewSingleHostReverseProxy(u)
	{
		defaultTransport := (http.DefaultTransport).(*http.Transport).Clone()
		defaultTransport.Proxy = nil
		proxy.Transport = defaultTransport
	}
	{
		defaultDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			userAgent := req.UserAgent()
			defaultDirector(req)
			req.Header.Set("User-Agent", userAgent)
			req.Header.Del("Accept-Encoding")
		}
	}
	handler := &Handler{
		config: config,
	}
	proxy.ModifyResponse = handler.handle
	proxy.ErrorHandler = handler.handleError
	return proxy, nil
}

func (_this *Handler) handleHeader(customDirectivesDesc string, requiredDirectiveMultimap multimap.MultiMap[string, FetchDirectiveItem]) (string, error) {
	customDirectiveMultipmap, err := _this.directiveDescToDirectives(customDirectivesDesc)
	if err != nil {
		return "", err
	}
	requiredDirectiveMultimap = merge(requiredDirectiveMultimap, customDirectiveMultipmap)
	csp := _this.config.ContentSecurityPolicy.Template
	for _, directiveType := range requiredDirectiveMultimap.KeySet() {
		directiveRegex := regexp2.MustCompile(fmt.Sprintf(`(%s)-src([^;]*)(;|$)`, directiveType), regexp2.None)
		directiveMatch, err := directiveRegex.FindStringMatch(csp)
		if err != nil {
			return "", err
		}
		requiredItems, _ := requiredDirectiveMultimap.Get(directiveType)

		var missingItems []FetchDirectiveItem
		directiveExists := directiveMatch != nil
		if directiveExists {
			existingItems, err := _this.directiveDescToDirectiveItems(directiveMatch.String())
			if err != nil {
				return "", err
			}
			missingItems = filter(requiredItems, func(item FetchDirectiveItem) bool {
				return !existingItems.Has(item)
			})
		} else {
			missingItems = requiredItems
		}

		if len(missingItems) > 0 {
			var missingItemsText string
			for _, inlineSource := range missingItems {
				missingItemsText += fmt.Sprintf(` '%s-%s'`, inlineSource.Type, inlineSource.Value)
			}
			if directiveExists {
				csp, err = directiveRegex.Replace(csp, fmt.Sprintf(`$1-src$2%s$3`, missingItemsText), -1, -1)
				if err != nil {
					return "", err
				}
			} else {
				csp += fmt.Sprintf(`; %s-src %s`, directiveType, missingItemsText)
			}
		}
	}
	return csp, nil
}

func (_this *Handler) handleDirectiveTags(body string) (string, *setmultimap.MultiMap[string, FetchDirectiveItem]) {
	var (
		compile = func(pattern string) *regexp2.Regexp {
			return regexp2.MustCompile(pattern, regexp2.IgnoreCase|regexp2.Singleline)
		}
		tagRegex         = compile(`<\s*(?<tag>script|style)(?<properties>[^>]*)>(?<body>.*?)(?<closedTag><\s*\/\s*\k<tag>\s*>)`)
		scriptNonceRegex = compile(`nonce\s*=\s*(["'])([^"']*)\1`)
		scriptSrcRegex   = compile(`src\s*=\s*(["'])([^"']*)\1`)
	)
	var requiredDirectiveMultimap = setmultimap.New[string, FetchDirectiveItem]()
	var randGenerator *RandGenerator
	newBody, err := tagRegex.ReplaceFunc(body, func(scriptMatch regexp2.Match) string {
		directiveType := scriptMatch.GroupByName("tag").String()
		strictDynamic := _this.containsStrictDynamic(directiveType)
		if !strictDynamic {
			if directiveType == "script" && !parseBool(_this.config.ContentSecurityPolicy.InlineScriptSrc) {
				return scriptMatch.String()
			}
			if directiveType == "style" && !parseBool(_this.config.ContentSecurityPolicy.InlineStyleSrc) {
				return scriptMatch.String()
			}
		}

		/*
		   3 cases:
		   1. nonce exists
		      append to header directly
		   2. 'strict dynamic' and src exist
		      generate nonce and then append to tag and header both
		   3. body exists
		      generate nonce or hash randomly and then append to tag and header both
		*/
		scriptProperties := scriptMatch.GroupByName("properties").String()
		scriptNonceMatch, err := scriptNonceRegex.FindStringMatch(scriptProperties)
		if err != nil {
			panic(err)
		}
		var (
			inlineSourceAppendingToHeader FetchDirectiveItem
			appendToTag                   bool
		)
		if scriptNonceMatch != nil {
			//if nonce exists
			inlineSourceAppendingToHeader.Type = "nonce"
			inlineSourceAppendingToHeader.Value = scriptNonceMatch.Groups()[2].String()
			appendToTag = false
		} else {
			scriptSrcMatch, err := scriptSrcRegex.FindStringMatch(scriptProperties)
			if err != nil {
				panic(err)
			}
			if randGenerator == nil {
				randGenerator = NewRandRandGenerator(_this.config.ContentSecurityPolicy.InlineTypes, true)
			}
			scriptBody := scriptMatch.GroupByName("body").String()
			var generator Generator
			if scriptSrcMatch != nil {
				//if 'strict dynamic' and src exists
				generator = randGenerator.ReusableNoncer()
			} else if strings.TrimSpace(scriptBody) != "" {
				//if javascript inline body exists
				generator = randGenerator.Next()
			}
			if generator != nil {
				inlineSourceAppendingToHeader.Type = generator.Name()
				inlineSourceAppendingToHeader.Value = generator.Generate(scriptBody)
				appendToTag = generator.AppendToTags()
			}
		}
		if inlineSourceAppendingToHeader.Type != "" {
			requiredDirectiveMultimap.Put(directiveType, inlineSourceAppendingToHeader)
		}
		if !appendToTag {
			return scriptMatch.String()
		}

		//`<\s*(?<tag>script|style)(?<properties>[^>]*)>(?<body>.*?)(?<closedTag><\s*\/\s*\k<tag>\s*>)`
		newScript := fmt.Sprintf(
			`<%s%s %s="%s">%s%s`,
			directiveType,
			scriptMatch.GroupByName("properties").String(),
			inlineSourceAppendingToHeader.Type,
			inlineSourceAppendingToHeader.Value,
			scriptMatch.GroupByName("body"),
			scriptMatch.GroupByName("closedTag"),
		)
		return newScript
	}, -1, -1)
	if err != nil {
		panic(err)
	}

	return newBody, requiredDirectiveMultimap
}

func (_this *Handler) handleUITags(body string) string {
	body1, listeners := _this.removeInlineHandlers(body)
	body2 := _this.convertInlineHandlersToScript(body1, listeners)
	return body2
}

func (_this *Handler) convertInlineHandlersToScript(body string, listeners []string) string {
	if len(listeners) > 0 {
		newScript := fmt.Sprintf("<script>\n%s\n</script>", strings.Join(listeners, "\n"))
		lastClosedIndex := strings.LastIndex(body, "<")
		htmlClosedTagRegex := regexp2.MustCompile(`<\s*/\s*html\s*>\s*$`, regexp2.IgnoreCase|regexp2.Singleline)
		htmlClosedTagMatch, err := htmlClosedTagRegex.FindStringMatchStartingAt(body, lastClosedIndex)
		if err != nil {
			panic(err)
		}
		if htmlClosedTagMatch == nil {
			return fmt.Sprintf("%s\n%s", body, newScript)
		}
		return fmt.Sprintf("%s%s\n</html>", string([]rune(body)[:htmlClosedTagMatch.Index]), newScript)
	}
	return body
}

// return new body whose inline listeners are removed & related listeners
func (_this *Handler) removeInlineHandlers(body string) (string, []string) {
	var handlers []string
	var (
		compile = func(pattern string) *regexp2.Regexp {
			return regexp2.MustCompile(pattern, regexp2.IgnoreCase|regexp2.Singleline)
		}
		uiOpenRegex         = compile(`<\s*(?<tag>\w+)[^>]*\s+(on\w+|href)\s*=[^>]*>`)
		idRegex             = compile(`\sid\s*=\s*((?<quote>["'])(?<id1>.+?)\k<quote>|(?<id2>[^\s>]+))`)
		inlineListenerRegex = compile(`\s(?<event>on\w+|href)\s*=\s*((?<quote>[\"'])\s*(?<body1>.*?)\k<quote>|(?<body2>[^\s>]*))`)
		scriptBodyRegex     = compile(`\s*(?<javascript>javascript\s*:)?(?<body>.*)`)
		looseUiOpenRegex    = compile(`<(.*?)>`)
	)
	newBody, err := uiOpenRegex.ReplaceFunc(body, func(uiOpenMatch regexp2.Match) string {
		uiOpenTag := uiOpenMatch.String()
		idMatch, err := idRegex.FindStringMatch(uiOpenTag)
		if err != nil {
			panic(err)
		}
		var id, idExists, requireAppendNewId = "", false, false
		if idMatch != nil {
			id = defaultIfEmpty(idMatch.GroupByName("id1").String(), idMatch.GroupByName("id2").String())
			idExists = true
		} else {
			id = _this.generateNewId(uiOpenMatch.GroupByName("tag").String())
		}
		newUiOpenTag, err := inlineListenerRegex.ReplaceFunc(uiOpenTag, func(inlineListenerMatch regexp2.Match) string {
			event := inlineListenerMatch.GroupByName("event").String()
			javascriptBody := defaultIfEmpty(inlineListenerMatch.GroupByName("body1").String(), inlineListenerMatch.GroupByName("body2").String())
			scriptBodyMatch, err := scriptBodyRegex.FindStringMatchStartingAt(javascriptBody, -1)
			if err != nil {
				panic(err)
			}
			//if normal href("javascript:" is not found after "href"), return original text
			if event == "href" && scriptBodyMatch.GroupByName("javascript").String() == "" {
				return inlineListenerMatch.String()
			}
			javascriptBody = strings.TrimSpace(scriptBodyMatch.GroupByName("body").String())
			if len(javascriptBody) == 0 {
				return inlineListenerMatch.String()
			}
			handlers = append(handlers, _this.convertToStandardScript(id, event, javascriptBody))
			if !idExists {
				requireAppendNewId = true
			}
			return ""
		}, -1, -1)
		if err != nil {
			panic(err)
		}
		if requireAppendNewId {
			newUiOpenTag, err = looseUiOpenRegex.Replace(newUiOpenTag, fmt.Sprintf(`<$1 id="%s">`, id), -1, -1)
			if err != nil {
				panic(err)
			}
		}
		return newUiOpenTag
	}, -1, -1)
	if err != nil {
		panic(err)
	}
	return newBody, handlers
}

func (_this *Handler) directiveDescToDirectives(directiveDesc string) (multimap.MultiMap[string, FetchDirectiveItem], error) {
	mmap := setmultimap.New[string, FetchDirectiveItem]()
	for _, directive := range strings.Split(directiveDesc, ";") {
		directiveType, subDirectiveDesc, found := strings.Cut(directive, " ")
		if found {
			directiveType, _, found = strings.Cut(directiveType, "-")
			if found {
				items, err := _this.directiveDescToDirectiveItems(subDirectiveDesc)
				if err != nil {
					return nil, err
				}
				items.Each(func(item FetchDirectiveItem) {
					mmap.Put(directiveType, item)
				})
			}
		}
	}
	return mmap, nil
}

func (_this *Handler) directiveDescToDirectiveItems(directiveDesc string) (*hashset.Set[FetchDirectiveItem], error) {
	existingItems := hashset.New[FetchDirectiveItem](5, generic.Equals[FetchDirectiveItem], func(e FetchDirectiveItem) uint64 {
		return generic.HashString(e.Type) ^ generic.HashString(e.Value)
	})
	existingItemRegex := regexp2.MustCompile(`'(nonce|sha\d+)-([\w\d+=\/]+)'`, regexp2.None)
	for existingItemMatch, err := existingItemRegex.FindStringMatch(directiveDesc); ; existingItemMatch, err = existingItemRegex.FindNextMatch(existingItemMatch) {
		if err != nil {
			return nil, err
		}
		if existingItemMatch == nil {
			break
		}
		element := FetchDirectiveItem{
			Type:  existingItemMatch.GroupByNumber(1).String(),
			Value: existingItemMatch.GroupByNumber(2).String(),
		}
		existingItems.Put(element)
	}
	return existingItems, nil
}

func (_this *Handler) convertToStandardScript(id, event, inlineHandler string) string {
	unescaped := html.UnescapeString(inlineHandler)
	thisParameterRegex := regexp2.MustCompile(`(\w[\w\d_]+\s*\()\s*this\s*(\))`, regexp2.IgnoreCase|regexp2.Singleline)
	handler2, err := thisParameterRegex.Replace(unescaped, fmt.Sprintf(`$1document.getElementById("%s")$2`, id), -1, -1)
	if err != nil {
		panic(err)
	}
	var s string
	if event == "href" {
		s += fmt.Sprintf(`
document.getElementById("%s").href = "#";
`, id)
		event = "onclick"
	}
	s += fmt.Sprintf(`
document.getElementById("%s").%s = function(event) {
	%s;
event.preventDefault();
};
`, id, event, handler2)
	return s
}

func (_this *Handler) containsStrictDynamic(directiveType string) bool {
	patternStrictDynamicRegex := regexp2.MustCompile(`(^|;)\s*(?<directive>[^-;]+)-src\s+[^;]*'strict-dynamic'\s+[^;]*(;|$)`, regexp2.IgnoreCase|regexp2.Singleline)
	for match, err := patternStrictDynamicRegex.FindStringMatch(_this.config.ContentSecurityPolicy.Template); ; match, err = patternStrictDynamicRegex.FindNextMatch(match) {
		if err != nil {
			panic(err)
		}
		if match == nil {
			return false
		}
		if match.GroupByName("directive").String() == directiveType {
			return true
		}
	}
}

func (_this *Handler) generateNewId(tag string) string {
	_this.RWMutex.RLock()
	if _this.idGenerator == nil {
		_this.RWMutex.RUnlock()
		_this.RWMutex.Lock()
		func() {
			defer _this.RWMutex.Unlock()
			if _this.idGenerator == nil {
				generator, err := nanoid.Standard(21)
				if err != nil {
					panic(err)
				}
				_this.idGenerator = generator
			}
		}()
	} else {
		_this.RWMutex.RUnlock()
	}
	return fmt.Sprintf(`%s-%s`, tag, _this.idGenerator())
}

func filter[V any](array []V, filterFunc func(V) bool) []V {
	var missingItems []V
	for _, item := range array {
		if filterFunc(item) {
			missingItems = append(missingItems, item)
		}
	}
	return missingItems
}

func merge[K comparable, V any](p, q multimap.MultiMap[K, V]) multimap.MultiMap[K, V] {
	for _, k := range q.KeySet() {
		v, found := q.Get(k)
		if found {
			p.PutAll(k, v)
		}
	}
	return p
}
