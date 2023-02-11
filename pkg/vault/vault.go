package vault

import (
	"io"
)

// ReadableVault provides read-only access to a vault.
//
// Get returns a fully-decrypted vault entry with all details.
//
// List returns all vault entries. Implementations should omit secret fields from entries returned
// by List.
type ReadableVault interface {
	io.Closer
	Get(id string) (Entry, bool)
	List() []Entry
}

// SearchableVault provides a way to search for entries in a vault.
//
// Find returns entries that match the provided condition. Implementations should omit secret
// fields from entries returned by Find.
type SearchableVault interface {
	Find(condition func(Entry) bool) []Entry
}

// WritableVault provides a way to manipulate entries in a vault.
//
// Put adds or replaces an entry.
//
// Delete removes an entry.
type WritableVault interface {
	io.Closer
	Put(id string, entry Entry) error
	Delete(id string) error
}
