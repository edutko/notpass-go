package v3

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"

	"notpass-go/internal/backend/passwordsafe/util"
)

type header struct {
	version         uint16
	uuid            uuid.UUID
	name            string
	description     string
	lastSavedAt     time.Time
	lastSavedByWhat string
	lastSavedByWhom string
	lastSavedOnHost string
	emptyGroups     []string
	ignoredFields   map[byte][]byte
}

func parseHeader(r record) (header, error) {
	h := header{}
	var errs *multierror.Error

	for _, f := range r.fields {
		err := h.set(f.typ, f.data)
		if err != nil {
			errs = multierror.Append(errs, err)
		}
	}

	return h, errs.ErrorOrNil()
}

func (h *header) set(typ byte, data []byte) error {
	var err error
	switch typ {
	case versionField:
		h.version = binary.LittleEndian.Uint16(data)
	case headerUuidField:
		h.uuid, err = uuid.FromBytes(data)
		if err != nil {
			err = fmt.Errorf("uuid.FromBytes: %w", err)
		}
	case lastSavedAtField:
		// https://github.com/pwsafe/pwsafe/blob/809a171cde0c7d984d81bfc911e5c4378d47cd7b/docs/formatV3.txt#L206
		if len(data) == 4 {
			h.lastSavedAt, err = util.ParseTimestamp(data)
		} else if len(data) == 8 {
			var ts []byte
			ts, err = hex.DecodeString(string(data))
			for i, j := 0, len(ts)-1; i < j; i, j = i+1, j-1 {
				ts[i], ts[j] = ts[j], ts[i]
			}
			h.lastSavedAt, err = util.ParseTimestamp(ts)
		} else {
			err = errors.New("expected 4 or 8 bytes for timestamp")
		}
	case lastSavedByWhatField:
		h.lastSavedByWhat = string(data)
	case lastSavedByWhomField:
		h.lastSavedByWhom = string(data)
	case lastSavedOnHostField:
		h.lastSavedOnHost = string(data)
	case databaseNameField:
		h.name = string(data)
	case databaseDescriptionField:
		h.description = string(data)
	case emptyGroupsField:
		h.emptyGroups = append(h.emptyGroups, string(data))
	default:
		if h.ignoredFields == nil {
			h.ignoredFields = make(map[byte][]byte, 0)
		}
		h.ignoredFields[typ] = data
	}
	return err
}

// https://github.com/pwsafe/pwsafe/blob/809a171cde0c7d984d81bfc911e5c4378d47cd7b/docs/formatV3.txt#L138
const (
	versionField                 byte = 0x00
	headerUuidField              byte = 0x01
	nonDefaultPreferencesField   byte = 0x02
	treeDisplayStatusField       byte = 0x03
	lastSavedAtField             byte = 0x04
	lastSavedByField             byte = 0x05 // Deprecated
	lastSavedByWhatField         byte = 0x06
	lastSavedByWhomField         byte = 0x07
	lastSavedOnHostField         byte = 0x08
	databaseNameField            byte = 0x09
	databaseDescriptionField     byte = 0x0a
	databaseFiltersField         byte = 0x0b
	recentlyUsedEntriesField     byte = 0x0f
	namedPasswordPoliciesField   byte = 0x10
	emptyGroupsField             byte = 0x11
	yubicoField                  byte = 0x12
	masterPasswordChangedAtField byte = 0x13
	endOfHeader                  byte = 0xff
)
