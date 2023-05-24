package v3

import (
	"fmt"

	"github.com/hashicorp/go-multierror"

	"notpass-go/pkg/vault"
)

func parseEntries(records []record) ([]vault.Entry, error) {
	var entries []vault.Entry
	var errs *multierror.Error

	for _, r := range records {
		e := vault.Entry{}
		for _, f := range r.fields {
			if x, ok := fieldMap[f.typ]; ok {
				value, err := x.parse(f.data)
				if err != nil {
					errs = multierror.Append(errs, err)
				}
				e = e.With(x.name, value)
			} else {
				k := fmt.Sprintf("0x%02x", f.typ)
				v, _ := asHexString(f.data)
				e = e.With(k, v)
			}
		}
		entries = append(entries, e)
	}

	return entries, errs.ErrorOrNil()
}

var fieldMap = map[byte]struct {
	name  string
	parse func([]byte) (vault.Value, error)
}{
	0x01: {vault.IdField, asUUIDString},
	0x02: {vault.GroupField, asString},
	0x03: {vault.NameField, asString},
	0x04: {vault.UsernameField, asString},
	0x05: {vault.NoteField, asSensitiveString},
	0x06: {vault.PasswordField, asSensitiveString},
	0x07: {"creationTime", asTimestamp},
	0x08: {"passwordModificationTime", asTimestamp},
	0x09: {"lastAccessTime", asTimestamp},
	0x0a: {"passwordExpiryTime", asTimestamp},
	0x0c: {"lastModificationTime", asTimestamp},
	0x0d: {vault.UrlField, asString},
	0x0e: {"autotype", asHexString},
	0x0f: {"passwordHistory", asHexString},
	0x10: {"passwordPolicy", asHexString},
	0x11: {"passwordExpiryInterval", asHexString},
	0x12: {"runCommand", asHexString},
	0x13: {"doubleClickAction", asHexString},
	0x14: {"email", asString},
	0x15: {"protectedEntry", asHexString},
	0x16: {"ownSymbolsForPassword", asHexString},
	0x17: {"shiftDoubleClickAction", asHexString},
	0x18: {"passwordPolicyName", asHexString},
	0x19: {"entryKeyboardShortcut", asHexString},

	// None of these are currently implemented by PasswordSafe.
	0x1b: {"twoFactorKeyField", asHexString},
	0x1c: {"creditCardNumberField", asHexString},
	0x1d: {"creditCardExpirationField", asHexString},
	0x1e: {"creditCardCVVField", asHexString},
	0x1f: {"creditCardPINField", asHexString},
	0x20: {"qrCodeField", asHexString},
	0xdf: {"unknownField", asHexString},
}

const (
	endOfRecord = byte(0xff)
)
