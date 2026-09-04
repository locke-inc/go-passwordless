// Package ad scans Active Directory over LDAPS using the operator's own
// credentials (no service account to create). Full LDAP query implementation
// lands in M1 (adds go-ldap dependency); this stub defines the config surface
// and validates inputs so the CLI is usable and honest today.
package ad

import (
	"errors"
	"fmt"
	"strings"

	"github.com/locke-inc/go-passwordless/internal/model"
)

type Config struct {
	DC      string // e.g. ldaps://dc01.corp.example.com
	BaseDN  string // e.g. DC=corp,DC=example,DC=com
	BindUPN string
}

// Validate checks config before any network touch.
func (c Config) Validate() error {
	if !strings.HasPrefix(strings.ToLower(c.DC), "ldaps://") {
		return errors.New("refusing non-LDAPS endpoint: use ldaps:// (plaintext LDAP is not allowed by default)")
	}
	if c.BaseDN == "" {
		return errors.New("base-dn is required (e.g. DC=corp,DC=example,DC=com)")
	}
	if c.BindUPN == "" {
		return errors.New("bind user is required: enter your own domain login (UPN); nothing is provisioned")
	}
	return nil
}

// Scan performs the read-only inventory pull. Currently returns a descriptive
// error until the M1 LDAP implementation lands.
func Scan(cfg Config, password string) (*model.Inventory, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("password required: prompted once, held in memory, never stored")
	}
	return nil, fmt.Errorf("ad scan: LDAP query engine not yet implemented (M1); config validated OK for %s", cfg.DC)
}
