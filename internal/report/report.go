// Package report renders the canonical JSON report and human-readable Markdown.
package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/locke-inc/go-passwordless/internal/assess"
	"github.com/locke-inc/go-passwordless/internal/cost"
	"github.com/locke-inc/go-passwordless/internal/model"
	"github.com/locke-inc/go-passwordless/internal/plan"
)

const SchemaVersion = "report/v1"

// Report is the canonical exportable document.
type Report struct {
	SchemaVersion string         `json:"schemaVersion"`
	Summary       assess.Result  `json:"summary"`
	Users         []model.User   `json:"users"`
	Apps          []model.App    `json:"apps"`
	Devices       []model.Device `json:"devices"`
	Phases        []plan.Phase   `json:"phases"`
	Cost          cost.Outputs   `json:"cost"`
}

// Build assembles a report from its parts.
func Build(inv *model.Inventory, r assess.Result, phases []plan.Phase, c cost.Outputs) Report {
	return Report{
		SchemaVersion: SchemaVersion,
		Summary:       r,
		Users:         inv.Users,
		Apps:          inv.Apps,
		Devices:       inv.Devices,
		Phases:        phases,
		Cost:          c,
	}
}

// ToJSON renders canonical JSON.
func ToJSON(r Report) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// ToMarkdown renders the human-readable handoff document.
func ToMarkdown(r Report) string {
	var b strings.Builder
	b.WriteString("# Passwordless Readiness Report\n\n")
	fmt.Fprintf(&b, "Ready now: %d | Needs remediation: %d | Exceptions: %d | Unknown: %d\n\n",
		r.Summary.ReadyNow, r.Summary.NeedsRemediation, r.Summary.Exceptions, r.Summary.Unknown)
	for _, p := range r.Phases {
		b.WriteString("## " + p.Name + "\n\n")
		for _, item := range p.Items {
			b.WriteString("- " + item + "\n")
		}
		b.WriteString("\n")
	}
	if len(r.Summary.Findings) > 0 {
		b.WriteString("## Blockers\n\n")
		for _, f := range r.Summary.Findings {
			fmt.Fprintf(&b, "- **%s** `%s`: %s (source: %s)\n", f.Category, f.Subject, f.Detail, f.Source)
		}
		b.WriteString("\n")
	}
	b.WriteString("## Cost of staying on passwords\n\n")
	if r.Cost.Complete {
		fmt.Fprintf(&b, "Estimated annual helpdesk cost of resets: $%.2f (from your inputs).\n\n", r.Cost.AnnualResetCost)
	} else {
		b.WriteString("Incomplete: provide resets/month, minutes/reset, and hourly rate to compute.\n\n")
	}
	if r.Cost.ProvidedBreachEstimate > 0 {
		fmt.Fprintf(&b, "Your estimated breach exposure: $%.2f (customer estimate, not Locke data).\n\n", r.Cost.ProvidedBreachEstimate)
	}
	b.WriteString("---\n\n")
	b.WriteString("Ready to implement? Use [open-passkey](https://github.com/locke-inc/open-passkey) ")
	b.WriteString("for drop-in WebAuthn/passkeys, or visit [lockeidentity.com](https://lockeidentity.com) ")
	b.WriteString("for a managed rollout.\n")
	return b.String()
}
