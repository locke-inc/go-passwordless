// Package entra scans Entra ID via Microsoft Graph using delegated
// device-code flow against the Locke multi-tenant app registration.
// The customer creates nothing: one admin-consent click in the wizard.
// The access token lives in memory for the scan only and is never stored.
package entra

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/locke-inc/go-passwordless/internal/model"
)

// Scopes are read-only least privilege. Device.Read.All covers the device
// inventory; no write or mail/file scopes are ever requested.
var Scopes = []string{
	"User.Read.All",
	"Policy.Read.All",
	"Device.Read.All",
	"AuditLog.Read.All",
}

type Config struct {
	Tenant   string // e.g. contoso.onmicrosoft.com
	ClientID string // Locke multi-tenant app; or GO_PASSWORDLESS_ENTRA_CLIENT_ID
}

// Validate checks config before any network touch.
func (c Config) Validate() error {
	if c.Tenant == "" {
		return errors.New("tenant is required (e.g. contoso.onmicrosoft.com)")
	}
	if c.ClientID == "" {
		return errors.New("no app registration configured yet: set --client-id or GO_PASSWORDLESS_ENTRA_CLIENT_ID (Locke multi-tenant app, pending)")
	}
	return nil
}

// Scan signs the operator in via device-code flow (one admin-consent click)
// and pulls a read-only inventory from Microsoft Graph.
func Scan(cfg Config) (*model.Inventory, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	token, err := deviceCodeToken(cfg)
	if err != nil {
		return nil, err
	}
	g := &graph{client: &http.Client{Timeout: 30 * time.Second}, token: token}
	inv := &model.Inventory{SchemaVersion: "inventory/v1"}

	pol, err := g.authMethodsPolicy()
	if err != nil {
		return nil, fmt.Errorf("authenticationMethodsPolicy: %w", err)
	}
	inv.Policy = pol

	users, err := g.users()
	if err != nil {
		return nil, fmt.Errorf("users: %w", err)
	}
	for i := range users {
		methods, err := g.userMethodTypes(users[i].ID)
		if err != nil {
			return nil, fmt.Errorf("auth methods for %s: %w", users[i].UPN, err)
		}
		users[i].HasPhishingRes = hasPhishingRes(methods)
	}
	inv.Users = users

	apps, err := g.servicePrincipals()
	if err != nil {
		return nil, fmt.Errorf("servicePrincipals: %w", err)
	}
	inv.Apps = apps

	devices, err := g.devices()
	if err != nil {
		return nil, fmt.Errorf("devices: %w", err)
	}
	inv.Devices = devices
	return inv, nil
}

// ResolveClientID prefers the explicit flag, then the environment.
func ResolveClientID(flag string) string {
	if flag != "" {
		return flag
	}
	return os.Getenv("GO_PASSWORDLESS_ENTRA_CLIENT_ID")
}

// --- device-code flow (stdlib only) ---

type deviceCodeResp struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	Message         string `json:"message"`
	Interval        int    `json:"interval"`
}

func deviceCodeToken(cfg Config) (string, error) {
	form := url.Values{
		"client_id": {cfg.ClientID},
		"scope":     {strings.Join(Scopes, " ")},
	}
	var dc deviceCodeResp
	if err := postForm("https://login.microsoftonline.com/"+cfg.Tenant+"/oauth2/v2.0/devicecode", form, &dc); err != nil {
		return "", err
	}
	fmt.Println(dc.Message)
	interval := dc.Interval
	if interval <= 0 {
		interval = 5
	}
	for {
		time.Sleep(time.Duration(interval) * time.Second)
		form := url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"client_id":   {cfg.ClientID},
			"device_code": {dc.DeviceCode},
		}
		var tr struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
		}
		if err := postForm("https://login.microsoftonline.com/"+cfg.Tenant+"/oauth2/v2.0/token", form, &tr); err != nil {
			return "", err
		}
		switch {
		case tr.AccessToken != "":
			return tr.AccessToken, nil
		case tr.Error == "authorization_pending":
			continue
		default:
			return "", fmt.Errorf("sign-in failed (%s); ask an admin to complete the consent click", tr.Error)
		}
	}
}

func postForm(endpoint string, form url.Values, out any) error {
	resp, err := http.PostForm(endpoint, form)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("auth endpoint: %w", err)
	}
	return nil
}

// --- Graph client ---

type graph struct {
	client *http.Client
	token  string
}

type page struct {
	Value    []json.RawMessage `json:"value"`
	NextLink string            `json:"@odata.nextLink"`
}

func (g *graph) getAll(endpoint string) ([][]byte, error) {
	var out [][]byte
	next := endpoint
	for next != "" {
		req, err := http.NewRequest("GET", next, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+g.token)
		resp, err := g.client.Do(req)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("graph %s: HTTP %d: %s", endpoint, resp.StatusCode, compact(raw))
		}
		var p page
		if err := json.Unmarshal(raw, &p); err != nil {
			return nil, err
		}
		for _, v := range p.Value {
			out = append(out, v)
		}
		next = p.NextLink
	}
	return out, nil
}

func compact(raw []byte) string {
	s := strings.TrimSpace(string(raw))
	if len(s) > 300 {
		return s[:300] + "..."
	}
	return s
}

const graphBase = "https://graph.microsoft.com/v1.0"

// authMethodsPolicy reads which phishing-resistant methods the tenant allows.
func (g *graph) authMethodsPolicy() (model.Policy, error) {
	raw, err := g.getOne(graphBase + "/policies/authenticationMethodsPolicy")
	if err != nil {
		return model.Policy{}, err
	}
	var pol struct {
		Configs []MethodConfig `json:"authenticationMethodConfigurations"`
	}
	if err := json.Unmarshal(raw, &pol); err != nil {
		return model.Policy{}, err
	}
	return policyFromConfigs(pol.Configs), nil
}

// MethodConfig is one entry of authenticationMethodConfigurations.
type MethodConfig struct {
	ID    string `json:"id"`
	State string `json:"state"`
}

func (g *graph) getOne(endpoint string) ([]byte, error) {
	req, err := http.NewRequest("GET", endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+g.token)
	resp, err := g.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, compact(raw))
	}
	return raw, nil
}

// policyFromConfigs maps Graph method configs to our policy. Pure: unit-tested.
func policyFromConfigs(configs []MethodConfig) model.Policy {
	p := model.Policy{Provenance: "entra:", Confidence: model.ConfidenceObserved}
	for _, c := range configs {
		if !strings.EqualFold(c.State, "enabled") {
			continue
		}
		switch c.ID {
		case "Fido2":
			p.FIDO2Allowed = true
		case "WindowsHelloForBusiness":
			p.WHfBAllowed = true
		}
	}
	return p
}

type graphUser struct {
	ID             string `json:"id"`
	UPN            string `json:"userPrincipalName"`
	AccountEnabled bool   `json:"accountEnabled"`
}

func (g *graph) users() ([]model.User, error) {
	raws, err := g.getAll(graphBase + "/users?$select=id,userPrincipalName,accountEnabled&$top=999")
	if err != nil {
		return nil, err
	}
	users := make([]model.User, 0, len(raws))
	for _, raw := range raws {
		var gu graphUser
		if err := json.Unmarshal(raw, &gu); err != nil {
			return nil, err
		}
		users = append(users, model.User{
			ID:         gu.ID,
			UPN:        gu.UPN,
			Enabled:    gu.AccountEnabled,
			Provenance: "entra:",
			Confidence: 1, // observed
		})
	}
	return users, nil
}

// userMethodTypes lists the @odata.type values of a user's auth methods.
func (g *graph) userMethodTypes(userID string) ([]string, error) {
	raws, err := g.getAll(graphBase + "/users/" + userID + "/authentication/methods?$select=id")
	if err != nil {
		return nil, err
	}
	var types []string
	for _, raw := range raws {
		var m struct {
			ODataType string `json:"@odata.type"`
		}
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, err
		}
		types = append(types, m.ODataType)
	}
	return types, nil
}

// hasPhishingRes reports whether any enrolled method resists phishing.
// Pure: unit-tested.
func hasPhishingRes(odataTypes []string) bool {
	for _, t := range odataTypes {
		switch t {
		case "#microsoft.graph.fido2AuthenticationMethod",
			"#microsoft.graph.windowsHelloForBusinessAuthenticationMethod":
			return true
		}
	}
	return false
}

func (g *graph) servicePrincipals() ([]model.App, error) {
	raws, err := g.getAll(graphBase + "/servicePrincipals?$select=id,appDisplayName,preferredSingleSignOnMode&$top=999")
	if err != nil {
		return nil, err
	}
	apps := make([]model.App, 0, len(raws))
	for _, raw := range raws {
		var sp struct {
			ID   string  `json:"id"`
			Name string  `json:"appDisplayName"`
			SSO  *string `json:"preferredSingleSignOnMode"`
		}
		if err := json.Unmarshal(raw, &sp); err != nil {
			return nil, err
		}
		mode := ""
		if sp.SSO != nil {
			mode = *sp.SSO
		}
		if sp.Name == "" {
			continue
		}
		apps = append(apps, model.App{
			ID:          sp.ID,
			Name:        sp.Name,
			SSOProtocol: ssoMode(mode),
			Provenance:  "entra:",
		})
	}
	return apps, nil
}

// ssoMode normalizes Graph SSO modes to our taxonomy. Pure: unit-tested.
func ssoMode(mode string) string {
	switch strings.ToLower(mode) {
	case "saml":
		return "saml"
	case "oidc":
		return "oidc"
	case "password", "passwordsso":
		return "password-sso"
	case "":
		return "none"
	default:
		return "none"
	}
}

func (g *graph) devices() ([]model.Device, error) {
	raws, err := g.getAll(graphBase + "/devices?$select=id,displayName,operatingSystem,operatingSystemVersion,trustType,isCompliant&$top=999")
	if err != nil {
		return nil, err
	}
	devices := make([]model.Device, 0, len(raws))
	for _, raw := range raws {
		var d struct {
			ID        string `json:"id"`
			Name      string `json:"displayName"`
			OS        string `json:"operatingSystem"`
			OSVersion string `json:"operatingSystemVersion"`
			Trust     string `json:"trustType"`
			Compliant bool   `json:"isCompliant"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			return nil, err
		}
		os := d.OS
		if d.OSVersion != "" {
			os += " " + d.OSVersion
		}
		devices = append(devices, model.Device{
			ID:         firstNonEmpty(d.Name, d.ID),
			OS:         os,
			JoinType:   trustType(d.Trust),
			Compliant:  d.Compliant,
			Provenance: "entra:",
			Confidence: 1, // observed
		})
	}
	return devices, nil
}

func trustType(t string) string {
	switch t {
	case "AzureAdJoined":
		return "Entra Joined"
	case "AzureAdRegistered":
		return "Entra Registered"
	case "HybridAzureAdJoined":
		return "Hybrid Joined"
	case "":
		return "Unknown"
	default:
		return t
	}
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
