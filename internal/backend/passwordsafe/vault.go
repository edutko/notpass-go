package passwordsafe

import (
	"fmt"

	"notpass-go/internal/backend/passwordsafe/dbfile"
	"notpass-go/internal/backend/passwordsafe/v3"
	"notpass-go/pkg/vault"
)

type Vault interface {
	vault.ReadableVault
	vault.SearchableVault
	Name() string
}

func OpenVault(dbFile, password string) (Vault, error) {
	f, err := dbfile.GuessFormat(dbFile, password)
	if err != nil {
		return nil, fmt.Errorf("dbfile.GuessFormat: %w", err)
	}

	switch f {
	case dbfile.V3Format:
		v, err := v3.OpenDb(dbFile, password)
		if err != nil {
			return nil, fmt.Errorf("v3.OpenDb: %w", err)
		}
		return v, nil

	default:
		return nil, fmt.Errorf("unsupported PasswordSafe database format (only v3 databases are supported)")
	}
}
