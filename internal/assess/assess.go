// Package assess classifies inventory entries into
// ready-now / needs-remediation / exception / unknown.
package assess

import (
	"github.com/locke-inc/go-passwordless/internal/model"
)

type Finding struct {
	Category string `json:"category"` // idp-policy, app-sso, device-capability, recovery-path, shared-account
	Subject  string `json:"subject"`
	Detail   string `json:"detail"`
	Source   string `json:"source"`
}

type Result struct {
	ReadyNow         int       `json:"readyNow"`
	NeedsRemediation int       `json:"needsRemediation"`
	Exceptions       int       `json:"exceptions"`
	Unknown          int       `json:"unknown"`
	Findings         []Finding `json:"findings"`
}

// Classify mutates user classes in place and returns aggregate counts.
func Classify(inv *model.Inventory) Result {
	var r Result
	for i := range inv.Users {
		u := &inv.Users[i]
		switch {
		case !u.Enabled:
			u.Class = model.ClassException
			u.ClassReason = "disabled account"
			r.Exceptions++
		case u.HasSPN:
			u.Class = model.ClassException
			u.ClassReason = "service account (SPN present); scope compensating control"
			r.Exceptions++
			r.Findings = append(r.Findings, Finding{
				Category: "shared-account", Subject: u.UPN,
				Detail: "service account cannot use interactive passkeys; isolate with managed identity or vaulted secret",
				Source: string(u.Provenance),
			})
		case u.HasPhishingRes || u.SmartcardRequired:
			u.Class = model.ClassReadyNow
			u.ClassReason = "phishing-resistant method already present"
			r.ReadyNow++
		case !inv.Policy.FIDO2Allowed && !inv.Policy.WHfBAllowed:
			u.Class = model.ClassNeedsRemediation
			u.ClassReason = "IdP policy does not allow FIDO2 or Windows Hello for Business"
			r.NeedsRemediation++
			r.Findings = append(r.Findings, Finding{
				Category: "idp-policy", Subject: u.UPN,
				Detail: "enable FIDO2 / platform-authenticator policy",
				Source: string(inv.Policy.Provenance),
			})
		default:
			u.Class = model.ClassNeedsRemediation
			u.ClassReason = "no phishing-resistant method enrolled; policy allows it"
			r.NeedsRemediation++
		}
	}
	for _, app := range inv.Apps {
		switch app.SSOProtocol {
		case "saml", "oidc", "ws-fed":
			// SSO-capable: ready path exists, counted as finding-free.
		case "password-sso", "link", "none", "":
			r.Findings = append(r.Findings, Finding{
				Category: "app-sso", Subject: app.Name,
				Detail: "app has no modern SSO protocol; needs remediation or exception",
				Source: string(app.Provenance),
			})
		}
	}
	for _, d := range inv.Devices {
		if d.Confidence == model.ConfidenceUnknown {
			r.Findings = append(r.Findings, Finding{
				Category: "device-capability", Subject: d.ID,
				Detail: "device capability not observed (no MDM signal); verify OS/TPM before rollout",
				Source: string(d.Provenance),
			})
		}
	}
	r.Unknown = countClass(inv.Users, model.ClassUnknown)
	return r
}

func countClass(users []model.User, c model.UserClass) int {
	n := 0
	for _, u := range users {
		if u.Class == c {
			n++
		}
	}
	return n
}
