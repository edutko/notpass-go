package sensitive

type String string

func (s String) AsString() string {
	return string(s)
}

func (s String) String() string {
	return Redacted
}

func (s String) GoString() string {
	return Redacted
}

const Redacted = "**********"
