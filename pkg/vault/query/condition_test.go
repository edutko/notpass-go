package query

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/pkg/vault"
)

func TestAny(t *testing.T) {
	assert.True(t, Any(vault.NewEntry()))
	assert.True(t, Any(vault.NewEntry().WithId("blah")))
	assert.True(t, Any(vault.NewEntry().With("foo", vault.String("bar"))))
}

func TestNone(t *testing.T) {
	assert.False(t, None(vault.NewEntry()))
	assert.False(t, None(vault.NewEntry().With("foo", vault.String("bar"))))
	assert.False(t, None(vault.NewEntry().WithId("blah")))
}

func TestAnd(t *testing.T) {
	assert.True(t, And(Any, Any)(vault.NewEntry()))
	assert.False(t, And(Any, None)(vault.NewEntry()))
	assert.False(t, And(None, Any)(vault.NewEntry()))
	assert.False(t, And(None, None)(vault.NewEntry()))
}

func TestOr(t *testing.T) {
	assert.True(t, Or(Any, Any)(vault.NewEntry()))
	assert.True(t, Or(Any, None)(vault.NewEntry()))
	assert.True(t, Or(None, Any)(vault.NewEntry()))
	assert.False(t, Or(None, None)(vault.NewEntry()))
}

func TestProperty_Contains(t *testing.T) {
	testCases := []struct {
		e        vault.Entry
		expected bool
	}{
		{vault.NewEntry().With("foo", vault.String("bar")), true},
		{vault.NewEntry().With("foo", vault.String("bbar")), true},
		{vault.NewEntry().With("foo", vault.String("barr")), true},
		{vault.NewEntry().With("foo", vault.String("bbarr")), true},

		{vault.NewEntry().With("foo", vault.String("baz")), false},
		{vault.NewEntry().With("foo", vault.String("")), false},
	}

	c := Where("foo").Contains("bar")

	for _, tc := range testCases {
		assert.Equal(t, tc.expected, c(tc.e))
	}
}

func TestProperty_Equals(t *testing.T) {
	testCases := []struct {
		e        vault.Entry
		expected bool
	}{
		{vault.NewEntry().With("foo", vault.String("bar")), true},

		{vault.NewEntry().With("foo", vault.String("baz")), false},
		{vault.NewEntry().With("foo", vault.String("")), false},
		{vault.NewEntry().With("foo", vault.String("bbar")), false},
		{vault.NewEntry().With("foo", vault.String("barr")), false},
		{vault.NewEntry().With("foo", vault.String("bbarr")), false},
	}

	c := Where("foo").Equals("bar")

	for _, tc := range testCases {
		assert.Equal(t, tc.expected, c(tc.e))
	}
}

func TestProperty_MatchesWildcard(t *testing.T) {
	testCases := []struct {
		e        vault.Entry
		pattern  string
		expected bool
	}{
		{vault.NewEntry().With("foo", vault.String("bar")), "bar", true},
		{vault.NewEntry().With("foo", vault.String("bbar")), "bar", false},
		{vault.NewEntry().With("foo", vault.String("barr")), "bar", false},
		{vault.NewEntry().With("foo", vault.String("bbarr")), "bar", false},
		{vault.NewEntry().With("foo", vault.String("foobar")), "bar", false},
		{vault.NewEntry().With("foo", vault.String("barbaz")), "bar", false},
		{vault.NewEntry().With("foo", vault.String("foobarbaz")), "bar", false},

		{vault.NewEntry().With("foo", vault.String("bar")), "bar*", true},
		{vault.NewEntry().With("foo", vault.String("bbar")), "bar*", false},
		{vault.NewEntry().With("foo", vault.String("barr")), "bar*", true},
		{vault.NewEntry().With("foo", vault.String("bbarr")), "bar*", false},
		{vault.NewEntry().With("foo", vault.String("foobar")), "bar*", false},
		{vault.NewEntry().With("foo", vault.String("barbaz")), "bar*", true},
		{vault.NewEntry().With("foo", vault.String("foobarbaz")), "bar*", false},

		{vault.NewEntry().With("foo", vault.String("bar")), "bar?", false},
		{vault.NewEntry().With("foo", vault.String("bbar")), "bar?", false},
		{vault.NewEntry().With("foo", vault.String("barr")), "bar?", true},
		{vault.NewEntry().With("foo", vault.String("bbarr")), "bar?", false},
		{vault.NewEntry().With("foo", vault.String("foobar")), "bar?", false},
		{vault.NewEntry().With("foo", vault.String("barbaz")), "bar?", false},
		{vault.NewEntry().With("foo", vault.String("foobarbaz")), "bar?", false},

		{vault.NewEntry().With("foo", vault.String("bar")), "*bar", true},
		{vault.NewEntry().With("foo", vault.String("bbar")), "*bar", true},
		{vault.NewEntry().With("foo", vault.String("barr")), "*bar", false},
		{vault.NewEntry().With("foo", vault.String("bbarr")), "*bar", false},
		{vault.NewEntry().With("foo", vault.String("foobar")), "*bar", true},
		{vault.NewEntry().With("foo", vault.String("barbaz")), "*bar", false},
		{vault.NewEntry().With("foo", vault.String("foobarbaz")), "*bar", false},

		{vault.NewEntry().With("foo", vault.String("bar")), "?bar", false},
		{vault.NewEntry().With("foo", vault.String("bbar")), "?bar", true},
		{vault.NewEntry().With("foo", vault.String("barr")), "?bar", false},
		{vault.NewEntry().With("foo", vault.String("bbarr")), "?bar", false},
		{vault.NewEntry().With("foo", vault.String("foobar")), "?bar", false},
		{vault.NewEntry().With("foo", vault.String("barbaz")), "?bar", false},
		{vault.NewEntry().With("foo", vault.String("foobarbaz")), "?bar", false},
	}

	for _, tc := range testCases {
		c := Where("foo").MatchesWildcard(tc.pattern)
		assert.Equal(t, tc.expected, c(tc.e), tc.pattern)
	}
}

func Test_wildcardPatternToRegexPattern(t *testing.T) {
	testCases := []struct {
		wildcard      string
		expectedRegex string
	}{
		{"*foo*", "foo"},
		{"foo*", "^foo"},
		{"*foo", "foo$"},
		{"foo*bar", "^foo.*bar$"},

		{"foo***", "^foo"},
		{"**foo", "foo$"},
		{"*****foo***", "foo"},
		{"foo**bar", "^foo.*bar$"},

		{"foo?", "^foo.$"},
		{"?foo", "^.foo$"},
		{"?foo?", "^.foo.$"},
		{"foo?ar", "^foo.ar$"},
	}

	for _, tc := range testCases {
		assert.Equal(t, tc.expectedRegex, wildcardPatternToRegexPattern(tc.wildcard))
	}
}
