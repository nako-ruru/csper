package main

import (
	"github.com/dlclark/regexp2"
	"golang.org/x/exp/slices"
	"runtime/debug"
)

func parseBool(flag string) bool {
	regex := regexp2.MustCompile(`^(y|t|yes|true|1|on)$`, regexp2.IgnoreCase)
	matched, err := regex.MatchString(flag)
	if err != nil {
		panic(err)
	}
	return matched
}

func defaultIfEmpty(s1, s2 string) string {
	if s1 != "" {
		return s1
	}
	return s2
}

func stack(depth int) []byte {
	stack := debug.Stack()
	var (
		i      = slices.Index(stack, '\n')
		header = stack[:i+1]
		tail   = stack[i+1:]
	)
	for d := 0; d < depth*2; d++ {
		tail = tail[slices.Index(tail, '\n')+1:]
	}
	return append(header, tail...)
}
