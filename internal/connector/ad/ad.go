// Package ad scans Active Directory over LDAPS using the operator's own
// credentials (no service account to create). All queries are read-only and
// limited to an explicit attribute allowlist — password hashes and secrets
// are never requested.
package ad

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/locke-inc/go-passwordless/internal/model"
)

// userAccountControl flag bits (subset we classify on).
const (
	uacDisabled       = 0x0002
	uacPasswdNotReq   = 0x0020
	uacDontExpirePass = 0x10000
	uacSmartcardReq   = 0x40000
)

type Config struct {
	DC      string // e.g. ldaps://dc01.corp.example.com
	BaseDN  string // e.g. DC=corp,DC=example,DC=com
	BindUPN string // operator's own login; nothing is provisioned
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

// UAC summarizes the userAccountControl bits relevant to passwordless.
type UAC struct {
	Disabled          bool
	PasswordNotReq    bool
	DontExpirePass    bool
	SmartcardRequired bool
}

// ParseUAC decodes the userAccountControl bitmask.
func ParseUAC(raw string) UAC {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return UAC{}
	}
	return UAC{
		Disabled:          n&uacDisabled != 0,
		PasswordNotReq:    n&uacPasswdNotReq != 0,
		DontExpirePass:    n&uacDontExpirePass != 0,
		SmartcardRequired: n&uacSmartcardReq != 0,
	}
}

const pageSize = 500

var userAttrs = []string{
	"sAMAccountName",
	"userPrincipalName",
	"userAccountControl",
	"servicePrincipalName",
	"msDS-KeyCredentialLink", // Windows Hello for Business enrollment signal
	"pwdLastSet",
	"lockoutTime",
}

var computerAttrs = []string{
	"dNSHostName",
	"cn",
	"operatingSystem",
	"operatingSystemVersion",
	"userAccountControl",
}

// Scan binds with the operator's credentials and pulls a read-only inventory.
func Scan(cfg Config, password string) (*model.Inventory, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if password == "" {
		return nil, errors.New("password required: prompted once, held in memory, never stored")
	}
	conn, err := ldap.DialURL(cfg.DC)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", cfg.DC, err)
	}
	defer conn.Close()
	if err := conn.Bind(cfg.BindUPN, password); err != nil {
		return nil, fmt.Errorf("bind as %s failed (check login; nothing was changed): %w", cfg.BindUPN, err)
	}

	inv := &model.Inventory{SchemaVersion: "inventory/v1"}
	if err := scanUsers(conn, cfg.BaseDN, inv); err != nil {
		return nil, err
	}
	if err := scanComputers(conn, cfg.BaseDN, inv); err != nil {
		return nil, err
	}
	// AD exposes no central FIDO2-allowed flag over LDAP; capability is
	// observed per-user via KeyCredentialLink / smartcard-required instead.
	inv.Policy = model.Policy{Provenance: "ad:", Confidence: model.ConfidenceUnknown}
	return inv, nil
}

func scanUsers(conn *ldap.Conn, baseDN string, inv *model.Inventory) error {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(&(objectClass=user)(objectCategory=person))",
		userAttrs,
		nil,
	)
	return pagedSearch(conn, req, func(e *ldap.Entry) {
		uac := ParseUAC(e.GetAttributeValue("userAccountControl"))
		upn := e.GetAttributeValue("userPrincipalName")
		if upn == "" {
			upn = e.GetAttributeValue("sAMAccountName")
		}
		inv.Users = append(inv.Users, model.User{
			ID:                e.DN,
			UPN:               upn,
			Enabled:           !uac.Disabled,
			SmartcardRequired: uac.SmartcardRequired,
			PasswordNotReq:    uac.PasswordNotReq,
			// KeyCredentialLink presence means a WHfB key is registered:
			// phishing-resistant auth already in use.
			HasPhishingRes: uac.SmartcardRequired || len(e.GetAttributeValues("msDS-KeyCredentialLink")) > 0,
			HasSPN:         len(e.GetAttributeValues("servicePrincipalName")) > 0,
			Provenance:     "ad:",
			Confidence:     model.ConfidenceObserved,
		})
	})
}

func scanComputers(conn *ldap.Conn, baseDN string, inv *model.Inventory) error {
	req := ldap.NewSearchRequest(
		baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=computer)",
		computerAttrs,
		nil,
	)
	return pagedSearch(conn, req, func(e *ldap.Entry) {
		name := e.GetAttributeValue("dNSHostName")
		if name == "" {
			name = e.GetAttributeValue("cn")
		}
		os := e.GetAttributeValue("operatingSystem")
		if v := e.GetAttributeValue("operatingSystemVersion"); v != "" {
			os += " " + v
		}
		inv.Devices = append(inv.Devices, model.Device{
			ID:         name,
			OS:         os,
			JoinType:   "Domain Joined",
			Provenance: "ad:",
			// No MDM signal over LDAP: compliance is genuinely unknown.
			Confidence: model.ConfidenceUnknown,
		})
	})
}

func pagedSearch(conn *ldap.Conn, req *ldap.SearchRequest, fn func(*ldap.Entry)) error {
	// SearchWithPaging follows the page cookie internally until exhausted.
	res, err := conn.SearchWithPaging(req, pageSize)
	if err != nil {
		return fmt.Errorf("ldap search %q: %w", req.Filter, err)
	}
	for _, e := range res.Entries {
		fn(e)
	}
	return nil
}
