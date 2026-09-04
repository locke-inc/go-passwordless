package entra

import (
	"testing"

	"github.com/locke-inc/go-passwordless/internal/model"
)

func TestPolicyFromConfigs(t *testing.T) {
	p := policyFromConfigs([]MethodConfig{
		{ID: "Fido2", State: "enabled"},
		{ID: "WindowsHelloForBusiness", State: "disabled"},
		{ID: "Password", State: "enabled"}, // irrelevant to passwordless
	})
	if !p.FIDO2Allowed || p.WHfBAllowed {
		t.Fatalf("got %+v, want FIDO2 allowed only", p)
	}
	if p.Provenance != "entra:" || p.Confidence != model.ConfidenceObserved {
		t.Fatalf("provenance/confidence wrong: %+v", p)
	}
	if got := policyFromConfigs(nil); got.FIDO2Allowed || got.WHfBAllowed {
		t.Fatalf("empty configs must allow nothing: %+v", got)
	}
}

func TestHasPhishingRes(t *testing.T) {
	if !hasPhishingRes([]string{"#microsoft.graph.fido2AuthenticationMethod"}) {
		t.Fatal("fido2 must count")
	}
	if !hasPhishingRes([]string{"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod"}) {
		t.Fatal("WHfB must count")
	}
	if hasPhishingRes([]string{
		"#microsoft.graph.passwordAuthenticationMethod",
		"#microsoft.graph.phoneAuthenticationMethod",
	}) {
		t.Fatal("password/phone must not count")
	}
	if hasPhishingRes(nil) {
		t.Fatal("no methods must not count")
	}
}

func TestSSOMode(t *testing.T) {
	cases := map[string]string{
		"saml": "saml", "oidc": "oidc", "password": "password-sso", "": "none", "weird": "none",
	}
	for in, want := range cases {
		if got := ssoMode(in); got != want {
			t.Fatalf("ssoMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := (Config{Tenant: "t", ClientID: "c"}).Validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := (Config{Tenant: "t"}).Validate(); err == nil {
		t.Fatal("missing client ID must be rejected with guidance")
	}
	if err := (Config{}).Validate(); err == nil {
		t.Fatal("missing tenant must be rejected")
	}
}
