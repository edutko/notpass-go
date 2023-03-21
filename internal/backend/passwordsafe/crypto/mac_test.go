package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/internal/testutil"
)

func TestV1V2Mac(t *testing.T) {
	testCases := []struct {
		password string
		rnd      string
		expected string
	}{
		{"hunter2", "859f894709ddc59e", "be3af3d291e3b7c2e41d3350ba2a592350e211fa"},
		{"hunter2", "14880171bf18b437", "cfb02b4034146f056f50831d985870b58abbe194"},
	}

	for _, tc := range testCases {
		expected := testutil.UnHex(tc.expected)
		actual := V1V2Mac([]byte(tc.password), testutil.UnHex(tc.rnd))

		assert.Equal(t, expected, actual)
	}
}
