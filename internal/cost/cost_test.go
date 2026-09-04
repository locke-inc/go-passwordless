package cost

import "testing"

func TestAnnual(t *testing.T) {
	out := Annual(Inputs{ResetsPerMonth: 120, MinutesPerReset: 15, HourlyRate: 45})
	// 120*12*(15/60)*45 = 16200
	if out.AnnualResetCost != 16200 || !out.Complete {
		t.Fatalf("got %+v", out)
	}
}

func TestAnnualIncomplete(t *testing.T) {
	out := Annual(Inputs{})
	if out.Complete {
		t.Fatalf("empty inputs must be incomplete, got %+v", out)
	}
}
