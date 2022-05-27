package main

import (
	"bytes"
	"fmt"
	"github.com/dlclark/regexp2"
	"github.com/google/uuid"
	"github.com/zyedidia/generic"
	"github.com/zyedidia/generic/hashset"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type Handler struct {
	config Config
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
	if _this.config.ContentSecurityPolicy.InlineType == "" {
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
	defaultDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		userAgent := req.UserAgent()
		defaultDirector(req)
		req.Header.Set("User-Agent", userAgent)
		req.Header.Del("Accept-Encoding")
	}
	handler := &Handler{
		config: config,
	}
	proxy.ModifyResponse = handler.handle
	proxy.ErrorHandler = handler.handleError
	return proxy, nil
}

func (_this *Handler) handleHeader(requiredDirectives []FetchDirective) (string, error) {
	existingInlineRegex := regexp2.MustCompile(`'(nonce|sha\d+)-([\w\d+=/]+)'`, regexp2.None)
	csp := _this.config.ContentSecurityPolicy.Pattern
	for _, requiredDirective := range requiredDirectives {
		directiveRegex := regexp2.MustCompile(fmt.Sprintf(`(%s)-src([^;]*)(;|$)`, requiredDirective.Type), regexp2.None)
		directiveMatch, err := directiveRegex.FindStringMatch(csp)
		if err != nil {
			return "", err
		}
		if directiveMatch != nil {
			existingInlineMap := make(map[string]*hashset.Set[string])
			for existingInlineMatch, err := existingInlineRegex.FindStringMatch(directiveMatch.String()); ; existingInlineMatch, err = existingInlineRegex.FindNextMatch(existingInlineMatch) {
				if err != nil {
					return "", err
				}
				if existingInlineMatch == nil {
					break
				}
				inlineType := existingInlineMatch.Groups()[1].String()
				inlineValues, ok := existingInlineMap[inlineType]
				if !ok {
					inlineValues = hashset.New[string](10, generic.Equals[string], generic.HashString)
					existingInlineMap[inlineType] = inlineValues
				}
				inlineValues.Put(existingInlineMatch.Groups()[2].String())
			}
			inlineText := ""
			for _, inlineSource := range requiredDirective.InlineSources {
				if existingInline, ok := existingInlineMap[inlineSource.Type]; ok && existingInline.Has(inlineSource.Value) {
					continue
				}
				inlineText += fmt.Sprintf(` '%s-%s'`, inlineSource.Type, inlineSource.Value)
			}
			csp, err = directiveRegex.Replace(csp, fmt.Sprintf(`$1-src$2%s$3`, inlineText), -1, -1)
			if err != nil {
				panic(err)
			}
		} else {
			inlineText := ""
			for _, inlineSource := range requiredDirective.InlineSources {
				inlineText += fmt.Sprintf(` '%s-%s'`, inlineSource.Type, inlineSource.Value)
			}
			csp += fmt.Sprintf(`; %s-src %s`, requiredDirective.Type, inlineText)
		}
	}
	return csp, nil
}

func (_this *Handler) handleDirectiveTags(body string) (string, []FetchDirective) {
	tagRegex := regexp2.MustCompile(`<\s*(script|style)([^>]*)>(.*?)(<\s*\/\s*\1\s*>)`, regexp2.IgnoreCase|regexp2.Singleline)
	scriptNonceRegex := regexp2.MustCompile(`nonce\s*=\s*(["'])([^"']*)\1`, regexp2.IgnoreCase|regexp2.Singleline)

	var generator Generator
	var requiredDirectivesMap = make(map[string]*hashset.Set[InlineSource])

	newBody, err := tagRegex.ReplaceFunc(body, func(scriptMatch regexp2.Match) string {
		scriptMatchGroups := scriptMatch.Groups()

		directiveType := scriptMatchGroups[1].String()
		if directiveType == "script" && !_this.parseBool(_this.config.ContentSecurityPolicy.InlineScriptSrc) {
			return scriptMatch.String()
		}
		if directiveType == "style" && !_this.parseBool(_this.config.ContentSecurityPolicy.InlineStyleSrc) {
			return scriptMatch.String()
		}

		scriptProperties := scriptMatchGroups[2].String()
		scriptCspMatch, err := scriptNonceRegex.FindStringMatch(scriptProperties)
		if err != nil {
			panic(err)
		}

		var inlineSource InlineSource
		if scriptCspMatch != nil {
			inlineSource.Type = "nonce"
			inlineSource.Value = scriptCspMatch.Groups()[2].String()
		} else {
			if generator == nil {
				generator = NewGenerator(_this.config.ContentSecurityPolicy.InlineType)
			}
			inlineSource.Type = generator.Name()
			inlineSource.Value = generator.Generate(scriptMatchGroups[3].String())
		}

		r, ok := requiredDirectivesMap[directiveType]
		if !ok {
			r = hashset.New[InlineSource](5, generic.Equals[InlineSource], func(e InlineSource) uint64 {
				return generic.HashString(e.Type) ^ generic.HashString(e.Value)
			})
			requiredDirectivesMap[directiveType] = r
		}
		r.Put(inlineSource)

		if scriptCspMatch != nil || !generator.AppendToTags() {
			return scriptMatch.String()
		}

		//`<\s*(script|style)([^>]*)>(.*?)(<\s*\/\s*\1\s*>)`
		newScript := fmt.Sprintf(
			`<%s%s nonce="%s">%s%s`,
			directiveType,
			scriptMatchGroups[2].String(),
			inlineSource.Value,
			scriptMatchGroups[3].String(),
			scriptMatchGroups[4].String(),
		)
		return newScript
	}, -1, -1)
	if err != nil {
		panic(err)
	}
	var requiredDirectives []FetchDirective
	for directiveType, inlineSources := range requiredDirectivesMap {
		directive := FetchDirective{Type: directiveType}
		inlineSources.Each(func(inlineSource InlineSource) {
			directive.InlineSources = append(directive.InlineSources, inlineSource)
		})
		requiredDirectives = append(requiredDirectives, directive)
	}
	return newBody, requiredDirectives
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
		uiOpenRegex         = regexp2.MustCompile(`<\s*\w+[^>]*\s+(on\w+|href)\s*=[^>]*>`, regexp2.IgnoreCase|regexp2.Singleline)
		idRegex             = regexp2.MustCompile(`id\s*=\s*((?<quote>["'])(?<id1>.+?)\k<quote>|(?<id2>[^\s>]+))`, regexp2.IgnoreCase|regexp2.Singleline)
		inlineListenerRegex = regexp2.MustCompile(`\s(?<event>on\w+|href)\s*=\s*((?<quote>[\"'])\s*(?<body1>.*?)\k<quote>|(?<body2>[^\s>]*))`, regexp2.IgnoreCase|regexp2.Singleline)
		scriptBodyRegex     = regexp2.MustCompile(`\s*(?<javascript>javascript\s*:)?(?<body>.*)`, regexp2.IgnoreCase|regexp2.Singleline)
		looseUiOpenRegex    = regexp2.MustCompile(`<(.*?)>`, regexp2.IgnoreCase|regexp2.Singleline)
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
		} else {
			id = _this.generateNewId()
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

func (_this *Handler) convertToStandardScript(id, event, inlineHandler string) string {
	thisParameterRegex := regexp2.MustCompile(`(\w[\w\d_]+\s*\()\s*this\s*(\))`, regexp2.IgnoreCase|regexp2.Singleline)
	handler2, err := thisParameterRegex.Replace(inlineHandler, fmt.Sprintf(`$1document.getElementById("%s")$2`, id), -1, -1)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf(`
document.getElementById("%s").%s = function(event) {
	%s;
};
`, id, event, handler2)
}

func (_this *Handler) parseBool(flag string) bool {
	regex := regexp2.MustCompile(`^(y|t|yes|true|1)$`, regexp2.IgnoreCase)
	matched, err := regex.MatchString(flag)
	if err != nil {
		panic(err)
	}
	return matched
}

func (_this *Handler) generateNewId() string {
	return uuid.New().String()
}

func defaultIfEmpty(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}
