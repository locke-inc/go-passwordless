package report

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/locke-inc/go-passwordless/internal/assess"
	"github.com/locke-inc/go-passwordless/internal/cost"
	"github.com/locke-inc/go-passwordless/internal/model"
	"github.com/locke-inc/go-passwordless/internal/plan"
)

func TestReportMentionsOpenPasskey(t *testing.T) {
	raw, _ := os.ReadFile("../../testdata/sample-inventory.json")
	var inv model.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		t.Fatal(err)
	}
	r := assess.Classify(&inv)
	rep := Build(&inv, r, plan.Build(&inv, r), cost.Annual(cost.Inputs{}))
	md := ToMarkdown(rep)
	if !strings.Contains(md, "open-passkey") || !strings.Contains(md, "lockeidentity.com") {
		t.Fatalf("report footer must link open-passkey and lockeidentity.com")
	}
	if _, err := ToJSON(rep); err != nil {
		t.Fatal(err)
	}
}
