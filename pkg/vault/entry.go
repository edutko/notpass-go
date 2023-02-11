package vault

import "notpass-go/pkg/sensitive"

// NewEntry returns an Entry with an empty set of fields.
func NewEntry() Entry {
	return Entry{
		fields: make(map[string]Value, 0),
	}
}

// NewEntryWithFields returns an Entry with the specified fields.
func NewEntryWithFields(fields map[string]Value) Entry {
	fs := make(map[string]Value, len(fields))
	for k, v := range fields {
		fs[k] = v
	}
	return Entry{fs}
}

func (e Entry) Fields() map[string]Value {
	fs := make(map[string]Value, len(e.fields))
	for k, v := range e.fields {
		fs[k] = v
	}
	return fs
}

// WithoutSecrets returns a copy of the Entry that does not contain any secret fields.
func (e Entry) WithoutSecrets() Entry {
	sanitized := NewEntry()
	for k, v := range e.fields {
		if _, isSensitive := v.(Secret); !isSensitive {
			sanitized.fields[k] = v
		}
	}
	return sanitized
}

// Id returns the value for the "id" field.
func (e Entry) Id() string {
	return e.getAsString(IdField)
}

func (e Entry) WithId(id string) Entry {
	return e.With(IdField, String(id))
}

// Group returns the value for the "group" field.
//
// Groups may be organized into a logical hierarchy by separating levels with a forward slash ("/").
// Literal forward slashes and backslashes should be escaped with a backslash.
func (e Entry) Group() string {
	return e.getAsString(GroupField)
}

func (e Entry) WithGroup(group string) Entry {
	return e.With(GroupField, String(group))
}

// Name returns the value for the "name" field.
func (e Entry) Name() string {
	return e.getAsString(NameField)
}

func (e Entry) WithName(name string) Entry {
	return e.With(NameField, String(name))
}

// Note returns the value for the "note" field.
func (e Entry) Note() sensitive.String {
	return e.getAsSensitiveString(NoteField)
}

func (e Entry) WithNote(note sensitive.String) Entry {
	return e.With(NoteField, note)
}

// Password returns the value for the "password" field.
func (e Entry) Password() sensitive.String {
	return e.getAsSensitiveString(PasswordField)
}

func (e Entry) WithPassword(password sensitive.String) Entry {
	return e.With(PasswordField, password)
}

func (e Entry) Username() string {
	return e.getAsString(UsernameField)
}

func (e Entry) WithUsername(username string) Entry {
	return e.With(UsernameField, String(username))
}

func (e Entry) Url() string {
	return e.getAsString(UrlField)
}

func (e Entry) WithUrl(url string) Entry {
	return e.With(UrlField, String(url))
}

func (e Entry) Get(field string) Value {
	return e.fields[field]
}

func (e Entry) getAsString(field string) string {
	if v := e.Get(field); v != nil {
		return v.AsString()
	} else {
		return ""
	}
}

func (e Entry) getAsSensitiveString(field string) sensitive.String {
	if v := e.Get(field); v != nil {
		return sensitive.String(v.AsString())
	} else {
		return ""
	}
}

func (e Entry) With(field string, value Value) Entry {
	if e.fields == nil {
		e.fields = make(map[string]Value, 0)
	}
	e.fields[field] = value
	return e
}

// Entry represents an item in a password manager datastore.
type Entry struct {
	fields map[string]Value
}

const (
	GroupField    = "group"
	IdField       = "id"
	NameField     = "name"
	NoteField     = "note"
	PasswordField = "password"
	UrlField      = "url"
	UsernameField = "username"
)
