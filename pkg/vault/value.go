package vault

import (
	"time"
)

var DefaultTimeFormat = "2006-01-02 15:04:05"

type Value interface {
	AsString() string
}

type Secret interface {
	Value
	String() string
	GoString() string
}

type String string

func (s String) AsString() string {
	return string(s)
}

type Timestamp time.Time

func (t Timestamp) AsString() string {
	return time.Time(t).Format(DefaultTimeFormat)
}
