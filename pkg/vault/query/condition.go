package query

import (
	"fmt"
	"regexp"
	"strings"

	"notpass-go/pkg/vault"
)

type Condition func(vault.Entry) bool

func Any(_ vault.Entry) bool {
	return true
}

func None(_ vault.Entry) bool {
	return false
}

func And(conditions ...Condition) Condition {
	return func(e vault.Entry) bool {
		for _, c := range conditions {
			if !c(e) {
				return false
			}
		}
		return true
	}
}

func Or(conditions ...Condition) Condition {
	return func(e vault.Entry) bool {
		for _, c := range conditions {
			if c(e) {
				return true
			}
		}
		return false
	}
}

type field struct {
	name string
}

func Where(name string) field {
	return field{name}
}

func (f field) Equals(value string) Condition {
	return func(e vault.Entry) bool {
		return e.Get(f.name).AsString() == value
	}
}

func (f field) Contains(value string) Condition {
	return func(e vault.Entry) bool {
		return strings.Contains(e.Get(f.name).AsString(), value)
	}
}

func (f field) MatchesWildcard(pattern string) Condition {
	r := wildcardPatternToRegex(pattern)
	return func(e vault.Entry) bool {
		return r.MatchString(e.Get(f.name).AsString())
	}
}

func wildcardPatternToRegex(pattern string) *regexp.Regexp {
	expr := wildcardPatternToRegexPattern(pattern)
	r, err := regexp.Compile(expr)
	if err != nil {
		panic(fmt.Errorf("invalid wildcard pattern (%s): %v", pattern, err))
	}
	return r
}

func wildcardPatternToRegexPattern(pattern string) string {
	expr := regexp.MustCompile(`\*+`).ReplaceAllString(pattern, "*")
	expr = regexp.QuoteMeta(expr)
	expr = strings.ReplaceAll(expr, "\\*", ".*")
	expr = strings.ReplaceAll(expr, "\\?", ".")
	if strings.HasPrefix(expr, ".*") {
		expr = strings.TrimPrefix(expr, ".*")
	} else {
		expr = "^" + expr
	}
	if strings.HasSuffix(expr, ".*") {
		expr = strings.TrimSuffix(expr, ".*")
	} else {
		expr = expr + "$"
	}
	return expr
}
