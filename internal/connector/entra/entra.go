// Package entra scans Entra ID via Microsoft Graph using delegated
// device-code flow against the Locke multi-tenant app registration.
// The customer creates nothing: one admin-consent click in the wizard.
package entra

import (
	"errors"

	"github.com/locke-inc/go-passwordless/internal/model"
)

type Config struct {
	Tenant string // e.g. contoso.onmicrosoft.com
}

// Validate checks config before any network touch.
func (c Config) Validate() error {
	if c.Tenant == "" {
		return errors.New("tenant is required (e.g. contoso.onmicrosoft.com)")
	}
	return nil
}

// Scan performs the read-only Graph pull. Currently returns a descriptive
// error until the M2 Graph implementation lands.
func Scan(cfg Config) (*model.Inventory, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return nil, errors.New("entra scan: Graph query engine not yet implemented (M2); sign in as an admin when prompted so one consent click grants read-only scopes")
}
