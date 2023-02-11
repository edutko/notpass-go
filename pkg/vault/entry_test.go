package vault

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"notpass-go/pkg/sensitive"
)

func TestNewEntryWithFields(t *testing.T) {
	e := NewEntryWithFields(map[string]Value{
		IdField: String("12345"),
	})

	assert.Equal(t, "12345", e.Id())
}

func TestEntry_Fields(t *testing.T) {
	e := NewEntry().WithId("123").WithName("foo").WithGroup("bar").WithPassword("hunter2").
		WithNote("shhh!").With("CustomSecret", sensitive.String("squeamish ossifrage"))

	fs := e.Fields()

	assert.Len(t, fs, 6)
	assert.Equal(t, String("123"), fs[IdField])
	assert.Equal(t, String("foo"), fs[NameField])
	assert.Equal(t, String("bar"), fs[GroupField])
	assert.Equal(t, sensitive.String("hunter2"), fs[PasswordField])
	assert.Equal(t, sensitive.String("shhh!"), fs[NoteField])
	assert.Equal(t, sensitive.String("squeamish ossifrage"), fs["CustomSecret"])
}

func TestEntry_Withers(t *testing.T) {
	assert.Equal(t, "foo", Entry{}.WithGroup("foo").Get(GroupField).AsString())
	assert.Equal(t, "foo", Entry{}.WithId("foo").Get(IdField).AsString())
	assert.Equal(t, "foo", Entry{}.WithName("foo").Get(NameField).AsString())
	assert.Equal(t, "foo", Entry{}.WithUrl("foo").Get(UrlField).AsString())
	assert.Equal(t, "foo", Entry{}.WithUsername("foo").Get(UsernameField).AsString())
	assert.Equal(t, "foo", Entry{}.With("bar", String("foo")).Get("bar").AsString())

	assert.Equal(t, sensitive.String("foo"), Entry{}.WithNote("foo").getAsSensitiveString(NoteField))
	assert.Equal(t, sensitive.String("foo"), Entry{}.WithPassword("foo").getAsSensitiveString(PasswordField))
	assert.Equal(t, sensitive.String("foo"), Entry{}.With("bar", sensitive.String("foo")).getAsSensitiveString("bar"))
}

func TestEntry_Getters(t *testing.T) {
	assert.Equal(t, "foo", Entry{}.With(GroupField, String("foo")).Group())
	assert.Equal(t, "foo", Entry{}.With(IdField, String("foo")).Id())
	assert.Equal(t, "foo", Entry{}.With(NameField, String("foo")).Name())
	assert.Equal(t, "foo", Entry{}.With(UrlField, String("foo")).Url())
	assert.Equal(t, "foo", Entry{}.With(UsernameField, String("foo")).Username())

	assert.Equal(t, sensitive.String("foo"), Entry{}.With(NoteField, sensitive.String("foo")).Note())
	assert.Equal(t, sensitive.String("foo"), Entry{}.With(PasswordField, String("foo")).Password())
}

func TestEntry_WithoutSecrets(t *testing.T) {
	e := NewEntry().WithId("123").WithName("foo").WithGroup("bar").WithPassword("hunter2").
		WithNote("shhh!").With("CustomSecret", sensitive.String("squeamish ossifrage"))

	e1 := e.WithoutSecrets()
	assert.Equal(t, "123", e1.Id())
	assert.Equal(t, "foo", e1.Name())
	assert.Equal(t, "bar", e1.Group())
	assert.Zero(t, e1.Password())
	assert.Zero(t, e1.Note())
	assert.Zero(t, e1.getAsString("CustomSecret"))
}
