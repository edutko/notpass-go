package v3

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"

	"notpass-go/pkg/vault"
)

const (
	testDb   = "testdata/test.psafe3"
	password = "hunter2"
)

func TestOpenDb(t *testing.T) {
	db, err := OpenDb(testDb, password)

	assert.Nil(t, err)
	assert.NotNil(t, db)

	assert.Equal(t, uuid.MustParse("a662b655-2b16-4e37-b5a7-789caa7828d0"), db.UUID())
	assert.Equal(t, "Test database", db.Name())
	assert.Equal(t, "For testing purposes only!", db.Description())
	assert.Len(t, db.List(), 9)

	assert.Equal(t, time.Date(2023, 4, 2, 19, 31, 36, 0, time.UTC), db.hdr.lastSavedAt.UTC())
	assert.Equal(t, "Password Safe V3.58", db.hdr.lastSavedByWhat)
	assert.Equal(t, "luke", db.hdr.lastSavedByWhom)
	assert.Equal(t, "OWENS-PC", db.hdr.lastSavedOnHost)
	assert.Len(t, db.hdr.emptyGroups, 3)

	err = db.Close()
	assert.Nil(t, err)
}

func TestOpenDb_oldTimestampFormat(t *testing.T) {
	db, err := OpenDb("testdata/test-3.08.psafe3", password)
	assert.Nil(t, err)

	assert.Equal(t, time.Date(2023, 4, 2, 19, 43, 53, 0, time.UTC), db.hdr.lastSavedAt.UTC())

	err = db.Close()
	assert.Nil(t, err)
}

func TestOpenDb_errors(t *testing.T) {
	testCases := []struct {
		dbFile   string
		password string
	}{
		{"testdata/nonexistent", password},
		{"testdata/test-bad-hmac.psafe3", password},
		{"testdata/test-short-ciphertext.psafe3", password},
		{testDb, "12345"},
	}

	for _, tc := range testCases {
		db, err := OpenDb(tc.dbFile, tc.password)
		assert.NotNil(t, err)
		assert.Nil(t, db)
	}
}

func TestDB_Get(t *testing.T) {
	testCases := []struct {
		id       string
		exists   bool
		group    string
		name     string
		username string
		password string
		url      string
		email    string
		note     string
	}{
		{"bcdc6634-9e1a-4657-8cbf-36a4bc1a09cd", true,
			"Finance", "Imperial Crypto Exchange", "lskywalker", "FBuvy7MVN=-k3n@qjs>WQEeL9",
			"https://palpatine-coin.example.com/", "luke@lars-moisture-farm.com", "This is a note."},
		{"18f02841-6278-4b04-b357-d0a8b783e142", true,
			"Ūňıćöɗɘ", "トッシェ駅", "ɭṳĸɛ", "*_l\\>(4:rIQECVOHB=a@0dqh",
			"http://toschestation.net/", "futurepilot7@tatooine-isp.net", "?????"}, // It appears that only ASCII notes are supported.
		{id: "", exists: false},
		{id: "12345", exists: false},
	}

	db, _ := OpenDb(testDb, password)
	defer closeDb(db)

	for _, tc := range testCases {
		e, found := db.Get(tc.id)

		assert.Equal(t, tc.exists, found)
		if tc.exists {
			assert.Equal(t, tc.id, e.Id())
			assert.Equal(t, tc.group, e.Group())
			assert.Equal(t, tc.name, e.Name())
			assert.Equal(t, tc.username, e.Username())
			assert.Equal(t, tc.password, e.Password().AsString())
			assert.Equal(t, tc.url, e.Url())
			assert.Equal(t, tc.email, e.Get("email").AsString())
			assert.Equal(t, tc.note, e.Note().AsString())
		}
	}
}

func TestDB_List(t *testing.T) {
	db, _ := OpenDb(testDb, password)
	defer closeDb(db)

	entries := db.List()

	assert.Len(t, entries, 9)
	for _, e := range entries {
		assert.NotEmpty(t, e.Id())
		assert.NotEmpty(t, e.Name())

		assert.Empty(t, e.Password())
		assert.Empty(t, e.Note())
	}
}

func TestDB_Find(t *testing.T) {
	db, _ := OpenDb(testDb, password)
	defer closeDb(db)

	entries := db.Find(func(e vault.Entry) bool {
		return e.Username() == "luke"
	})

	assert.Len(t, entries, 2)
	for _, e := range entries {
		assert.NotEmpty(t, e.Id())
		assert.NotEmpty(t, e.Name())

		assert.Empty(t, e.Password())
		assert.Empty(t, e.Note())
	}
}

func closeDb(db *DB) {
	_ = db.Close()
}
