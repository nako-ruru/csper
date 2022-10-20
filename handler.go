package main

import (
	"bytes"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/jaevor/go-nanoid"
	"github.com/relengxing/go-multimap/setmultimap"
	"github.com/zyedidia/generic"
	"github.com/zyedidia/generic/hashset"
	"html"
	"io"
	"io/ioutil"
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
			switch e.(type) {
			case error:
				err = e.(error)
				break
			default:
				err = fmt.Errorf("%v", e)
			}
		}
	}()
	resp.Header.Del("Vary")
	contentType := resp.Header.Get("Content-type")
	contentTypeRegex := regexp2.MustCompile(`^text/htm`, regexp2.IgnoreCase)
	matched, err := contentTypeRegex.MatchString(contentType)
	if err != nil {
		return
	}
	if !matched {
		return
	}
	defer func(body io.ReadCloser) {
		_ = body.Close()
	}(resp.Body)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	// Restore the io.ReadCloser to its original state
	resp.Body = ioutil.NopCloser(bytes.NewBuffer(body))

	if _this.config.ReportTo != "" {
		resp.Header.Set("REPORT-TO", _this.config.ReportTo)
	}
	if len(_this.config.ContentSecurityPolicy.InlineTypes) == 0 {
		if _this.config.ContentSecurityPolicy.Pattern != "" {
			resp.Header.Set("CONTENT-SECURITY-POLICY", _this.config.ContentSecurityPolicy.Pattern)
		}
		return
	}

	newBody := _this.handleUITags(string(body))
	newBody, requiredDirectives := _this.handleDirectiveTags(newBody)

	csp, err := _this.handleHeader(requiredDirectives)
	if err != nil {
		return
	}
	if strings.TrimSpace(csp) != "" {
		resp.Header.Set("CONTENT-SECURITY-POLICY", csp)
	}

	buf := bytes.NewBufferString(newBody)
	resp.Body = ioutil.NopCloser(buf)
	return
}

func (_this *Handler) handleError(writer http.ResponseWriter, _ *http.Request, err error) {
	writer.WriteHeader(502)
	_, _ = writer.Write([]byte(err.Error()))
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

func (_this *Handler) handleHeader(requiredDirectiveMultimap *setmultimap.MultiMap[string, FetchDirectiveItem]) (string, error) {
	csp := _this.config.ContentSecurityPolicy.Pattern
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
	tagRegex := regexp2.MustCompile(`<\s*(?<tag>script|style)(?<properties>[^>]*)>(?<body>.*?)(?<closedTag><\s*\/\s*\k<tag>\s*>)`, regexp2.IgnoreCase|regexp2.Singleline)
	scriptNonceRegex := regexp2.MustCompile(`nonce\s*=\s*(["'])([^"']*)\1`, regexp2.IgnoreCase|regexp2.Singleline)
	scriptSrcRegex := regexp2.MustCompile(`src\s*=\s*(["'])([^"']*)\1`, regexp2.IgnoreCase|regexp2.Singleline)

	var requiredDirectiveMultimap = setmultimap.New[string, FetchDirectiveItem]()

	var randGenerator *RandGenerator
	newBody, err := tagRegex.ReplaceFunc(body, func(scriptMatch regexp2.Match) string {
		directiveType := scriptMatch.GroupByName("tag").String()
		if directiveType == "script" && !_this.parseBool(_this.config.ContentSecurityPolicy.InlineScriptSrc) {
			return scriptMatch.String()
		}
		if directiveType == "style" && !_this.parseBool(_this.config.ContentSecurityPolicy.InlineStyleSrc) {
			return scriptMatch.String()
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
			if scriptSrcMatch != nil && _this.containsStrictDynamic(directiveType) {
				//if 'strict dynamic' and src exists
				generator = randGenerator.ReusableNoncer()
			} else if strings.TrimSpace(scriptBody) != "" {
				//if javascript inline body exists
				generator = randGenerator.Next()
			}
			if generator != nil {
				inlineSourceAppendingToHeader.Type = generator.Name()
				inlineSourceAppendingToHeader.Value = generator.Generate(scriptBody)
				appendToTag = true
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
			if javascriptBody == "" {
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
	return fmt.Sprintf(`
document.getElementById("%s").%s = function(event) {
	%s;
};
`, id, event, handler2)
}

func (_this *Handler) containsStrictDynamic(directiveType string) bool {
	patternStrictDynamicRegex := regexp2.MustCompile(`(^|;)\s*(?<directive>[^-;]+)-src\s+[^;]*'strict-dynamic'\s+[^;]*(;|$)`, regexp2.IgnoreCase|regexp2.Singleline)
	for match, err := patternStrictDynamicRegex.FindStringMatch(_this.config.ContentSecurityPolicy.Pattern); ; match, err = patternStrictDynamicRegex.FindNextMatch(match) {
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

func (_this *Handler) parseBool(flag string) bool {
	regex := regexp2.MustCompile(`^(y|t|yes|true|1|on)$`, regexp2.IgnoreCase)
	matched, err := regex.MatchString(flag)
	if err != nil {
		panic(err)
	}
	return matched
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

func defaultIfEmpty(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}
