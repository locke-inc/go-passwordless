package ad

import "testing"

func TestParseUAC(t *testing.T) {
	// NORMAL_ACCOUNT (512) + DONT_EXPIRE_PASSWD (65536) = 66048
	u := ParseUAC("66048")
	if u.Disabled || !u.DontExpirePass || u.SmartcardRequired || u.PasswordNotReq {
		t.Fatalf("got %+v", u)
	}
	// + ACCOUNTDISABLE (2) + SMARTCARD_REQUIRED (262144) = 328194
	u = ParseUAC("328194")
	if !u.Disabled || !u.SmartcardRequired {
		t.Fatalf("got %+v", u)
	}
	if got := ParseUAC("not-a-number"); got != (UAC{}) {
		t.Fatalf("garbage input must yield zero UAC, got %+v", got)
	}
}

func TestValidate(t *testing.T) {
	ok := Config{DC: "ldaps://dc01.example.com", BaseDN: "DC=example,DC=com", BindUPN: "op@example.com"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	for _, bad := range []Config{
		{DC: "ldap://dc01.example.com", BaseDN: "DC=x", BindUPN: "u"}, // plaintext refused
		{DC: "ldaps://dc01.example.com"},                              // missing fields
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("invalid config accepted: %+v", bad)
		}
	}
}

func TestScanRefusesWithoutPassword(t *testing.T) {
	cfg := Config{DC: "ldaps://dc01.example.com", BaseDN: "DC=example,DC=com", BindUPN: "op@example.com"}
	if _, err := Scan(cfg, ""); err == nil {
		t.Fatal("empty password must be refused before any network touch")
	}
}
