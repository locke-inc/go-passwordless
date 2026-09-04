// Package plan generates a phased migration plan from assessment results.
package plan

import (
	"github.com/locke-inc/go-passwordless/internal/assess"
	"github.com/locke-inc/go-passwordless/internal/model"
)

type Phase struct {
	Name  string   `json:"name"`
	Items []string `json:"items"`
}

// Build returns ready-now / remediation / exception phases.
func Build(inv *model.Inventory, r assess.Result) []Phase {
	phases := []Phase{
		{Name: "Phase 1 — Ready now", Items: []string{}},
		{Name: "Phase 2 — Needs remediation", Items: []string{}},
		{Name: "Phase 3 — Exceptions", Items: []string{}},
	}
	for _, u := range inv.Users {
		switch u.Class {
		case model.ClassReadyNow:
			phases[0].Items = append(phases[0].Items, "Enroll "+u.UPN+" for passkeys (policy already allows it)")
		case model.ClassNeedsRemediation:
			phases[1].Items = append(phases[1].Items, "Remediate "+u.UPN+": "+u.ClassReason)
		case model.ClassException:
			phases[2].Items = append(phases[2].Items, "Scope compensating control for "+u.UPN+": "+u.ClassReason)
		default:
			phases[1].Items = append(phases[1].Items, "Verify "+u.UPN+": capability unknown, one targeted check needed")
		}
	}
	_ = r
	if len(phases[0].Items) == 0 {
		phases[0].Items = append(phases[0].Items, "No users ready yet — start with Phase 2 remediation items")
	}
	return phases
}
