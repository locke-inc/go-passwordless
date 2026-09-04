package assess

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/locke-inc/go-passwordless/internal/model"
)

func TestClassifySample(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/sample-inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inv model.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	r := Classify(&inv)
	if r.ReadyNow != 1 || r.NeedsRemediation != 1 || r.Exceptions != 1 {
		t.Fatalf("got %+v, want 1/1/1 across ready/remediate/exception", r)
	}
}

func TestClassifyBlockedPolicy(t *testing.T) {
	inv := model.Inventory{
		Policy: model.Policy{FIDO2Allowed: false, WHfBAllowed: false, Provenance: "ad:"},
		Users: []model.User{
			{UPN: "u@example.com", Enabled: true, Provenance: "ad:", Confidence: model.ConfidenceObserved},
		},
	}
	r := Classify(&inv)
	if r.NeedsRemediation != 1 {
		t.Fatalf("got %+v, want 1 needs-remediation", r)
	}
	if len(r.Findings) == 0 || r.Findings[0].Category != "idp-policy" {
		t.Fatalf("want idp-policy finding, got %+v", r.Findings)
	}
}
