// Package cost computes password-cost estimates from customer-supplied inputs
// ONLY. It ships no default breach statistics.
package cost

type Inputs struct {
	// All fields are customer-supplied. Zero means "not provided".
	ResetsPerMonth  float64 `json:"resetsPerMonth"`
	MinutesPerReset float64 `json:"minutesPerReset"`
	HourlyRate      float64 `json:"hourlyRate"`
	EstimatedBreach float64 `json:"estimatedBreachCost"`
}

type Outputs struct {
	AnnualResetCost        float64 `json:"annualResetCost"`
	ProvidedBreachEstimate float64 `json:"providedBreachEstimate"`
	Complete               bool    `json:"complete"` // false when inputs missing
}

// Annual computes the helpdesk cost of password resets.
func Annual(in Inputs) Outputs {
	if in.ResetsPerMonth <= 0 || in.MinutesPerReset <= 0 || in.HourlyRate <= 0 {
		return Outputs{ProvidedBreachEstimate: in.EstimatedBreach, Complete: false}
	}
	return Outputs{
		AnnualResetCost:        in.ResetsPerMonth * 12 * (in.MinutesPerReset / 60) * in.HourlyRate,
		ProvidedBreachEstimate: in.EstimatedBreach,
		Complete:               true,
	}
}
