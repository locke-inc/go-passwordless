// Package model defines the normalized, source-agnostic inventory that every
// connector produces and the assessment engine consumes.
package model

// Provenance prefixes: "ad:", "entra:", "user:".
type Provenance string

type Confidence int

const (
	ConfidenceUnknown  Confidence = iota // not observed
	ConfidenceInferred                   // derived from related signals
	ConfidenceObserved                   // read directly from the source
)

type UserClass int

const (
	ClassUnknown UserClass = iota
	ClassReadyNow
	ClassNeedsRemediation
	ClassException
)

func (c UserClass) String() string {
	switch c {
	case ClassReadyNow:
		return "ready-now"
	case ClassNeedsRemediation:
		return "needs-remediation"
	case ClassException:
		return "exception"
	default:
		return "unknown"
	}
}

type User struct {
	ID                string     `json:"id"`
	UPN               string     `json:"upn"`
	Enabled           bool       `json:"enabled"`
	SmartcardRequired bool       `json:"smartcardRequired"`
	PasswordNotReq    bool       `json:"passwordNotRequired"`
	HasPhishingRes    bool       `json:"hasPhishingResistant"`
	HasSPN            bool       `json:"hasSPN"`
	Class             UserClass  `json:"class"`
	ClassReason       string     `json:"classReason"`
	Provenance        Provenance `json:"provenance"`
	Confidence        Confidence `json:"confidence"`
}

type Device struct {
	ID         string     `json:"id"`
	OS         string     `json:"os"`
	JoinType   string     `json:"joinType"`
	Compliant  bool       `json:"compliant"`
	Provenance Provenance `json:"provenance"`
	Confidence Confidence `json:"confidence"`
}

type App struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	SSOProtocol string     `json:"ssoProtocol"` // saml, oidc, ws-fed, password-sso, link, none
	Provenance  Provenance `json:"provenance"`
}

type Policy struct {
	FIDO2Allowed bool       `json:"fido2Allowed"`
	WHfBAllowed  bool       `json:"whfbAllowed"`
	Provenance   Provenance `json:"provenance"`
	Confidence   Confidence `json:"confidence"`
}

type Inventory struct {
	SchemaVersion string   `json:"schemaVersion"`
	Users         []User   `json:"users"`
	Devices       []Device `json:"devices"`
	Apps          []App    `json:"apps"`
	Policy        Policy   `json:"policy"`
}
