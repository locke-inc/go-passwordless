// Command go-passwordless audits an environment for passwordless readiness.
//
// Usage:
//
//	go-passwordless start                                  interactive guided wizard
//	go-passwordless scan ad --dc ... --base-dn ...         AD inventory pull
//	go-passwordless scan entra --tenant ...                Entra inventory pull
//	go-passwordless assess --inventory a.json[,b.json] --org org.yaml --out report.json --format md
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/locke-inc/go-passwordless/internal/assess"
	adconn "github.com/locke-inc/go-passwordless/internal/connector/ad"
	entraconn "github.com/locke-inc/go-passwordless/internal/connector/entra"
	"github.com/locke-inc/go-passwordless/internal/cost"
	"github.com/locke-inc/go-passwordless/internal/model"
	"github.com/locke-inc/go-passwordless/internal/plan"
	"github.com/locke-inc/go-passwordless/internal/report"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "start":
		err = runStart()
	case "scan":
		err = runScan(os.Args[2:])
	case "assess":
		err = runAssess(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Println(`go-passwordless — find out how your org can go passwordless.

  go-passwordless start                 guided wizard (recommended)
  go-passwordless scan ad ...           scan Active Directory (LDAPS, your own login)
  go-passwordless scan entra ...        scan Entra ID (one admin-consent click)
  go-passwordless assess ...            build a readiness report from inventories

Nothing is changed in your environment. Reports stay on this machine.`)
}

func prompt(r *bufio.Reader, label string) string {
	fmt.Print(label + " ")
	s, _ := r.ReadString('\n')
	return strings.TrimSpace(s)
}

// readPassword prompts without echoing. Falls back to a visible prompt when
// stdin is not a terminal (pipes, tests).
func readPassword(label string) (string, error) {
	fmt.Print(label)
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		s, err := bufio.NewReader(os.Stdin).ReadString('\n')
		return strings.TrimSpace(s), err
	}
	raw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

// runStart is the zero-thinking wizard: detect, explain, validate step by step.
func runStart() error {
	r := bufio.NewReader(os.Stdin)
	fmt.Println("Welcome. I will check how your org can go passwordless.")
	fmt.Println("I only READ settings. Nothing will change. Reports stay on this machine.")
	fmt.Println()

	fmt.Println("[1/3] Where are your users?")
	fmt.Println("  1) Active Directory (on-prem)")
	fmt.Println("  2) Entra ID (Microsoft 365 / Azure)")
	fmt.Println("  3) Both")
	choice := prompt(r, "Pick 1, 2, or 3:")

	switch choice {
	case "1", "3":
		fmt.Println("\n-- Active Directory --")
		fmt.Println("I need your OWN Windows login so I can read directory settings.")
		fmt.Println("Nothing is created. Your password is used once and never stored.")
		dc := prompt(r, "Domain controller (e.g. ldaps://dc01.corp.example.com):")
		base := prompt(r, "Base DN (e.g. DC=corp,DC=example,DC=com):")
		upn := prompt(r, "Your login (e.g. you@corp.example.com):")
		cfg := adconn.Config{DC: dc, BaseDN: base, BindUPN: upn}
		if err := cfg.Validate(); err != nil {
			fmt.Printf("Not quite: %v\n", err)
			fmt.Println("Fix that and I will retry — nothing was touched.")
			return nil
		}
		fmt.Println("✓ AD details look good. (LDAP query engine lands in M1; config validated.)")
	case "2":
		fmt.Println("\n-- Entra ID --")
		tenant := prompt(r, "Your tenant (e.g. contoso.onmicrosoft.com):")
		if err := (entraconn.Config{Tenant: tenant}).Validate(); err != nil {
			fmt.Printf("Not quite: %v\n", err)
			return nil
		}
		fmt.Println("Next I would ask you to sign in as an admin and click Accept once")
		fmt.Println("on read-only permissions. (Graph query engine lands in M2.)")
		fmt.Println("If you are not an admin, grab yours for that one click.")
	default:
		fmt.Println("Pick 1, 2, or 3 and run me again — nothing was touched.")
		return nil
	}

	fmt.Println("\n[2/3] Economics (optional, your numbers only — I invent nothing).")
	fmt.Println("Skip anything you do not know; the report will say 'not provided'.")
	_ = prompt(r, "Password resets per month (or blank):")
	_ = prompt(r, "Minutes per reset (or blank):")

	fmt.Println("\n[3/3] Done for now. Next step:")
	fmt.Println("  Run: go-passwordless assess --inventory <file> --org org.yaml --out report.json --format md")
	fmt.Println("  Then implement with https://github.com/locke-inc/open-passkey")
	return nil
}

func runScan(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: go-passwordless scan [ad|entra] [flags]")
	}
	switch args[0] {
	case "ad":
		fs := flagSet(args[1:])
		dc := flagVal(fs, "dc")
		base := flagVal(fs, "base-dn")
		upn := flagVal(fs, "bind-user")
		out := flagVal(fs, "out")
		cfg := adconn.Config{DC: dc, BaseDN: base, BindUPN: upn}
		pw, err := readPassword("Password (used once, never stored): ")
		if err != nil {
			return err
		}
		inv, err := adconn.Scan(cfg, pw)
		if err != nil {
			return err
		}
		return writeInventory(out, inv)
	case "entra":
		fs := flagSet(args[1:])
		tenant := flagVal(fs, "tenant")
		out := flagVal(fs, "out")
		inv, err := entraconn.Scan(entraconn.Config{
			Tenant:   tenant,
			ClientID: entraconn.ResolveClientID(flagVal(fs, "client-id")),
		})
		if err != nil {
			return err
		}
		return writeInventory(out, inv)
	default:
		return fmt.Errorf("unknown scan source %q (want ad or entra)", args[0])
	}
}

func runAssess(args []string) error {
	fs := flagSet(args)
	invList := flagVal(fs, "inventory") // comma-separated
	orgPath := flagVal(fs, "org")
	out := flagVal(fs, "out")
	format := flagVal(fs, "format")
	if invList == "" || out == "" {
		return fmt.Errorf("usage: go-passwordless assess --inventory a.json[,b.json] [--org org.yaml] --out report.json [--format md]")
	}
	merged := &model.Inventory{SchemaVersion: "inventory/v1"}
	for _, p := range strings.Split(invList, ",") {
		inv, err := loadInventory(strings.TrimSpace(p))
		if err != nil {
			return err
		}
		merged.Users = append(merged.Users, inv.Users...)
		merged.Devices = append(merged.Devices, inv.Devices...)
		merged.Apps = append(merged.Apps, inv.Apps...)
		if inv.Policy.Provenance != "" {
			merged.Policy = inv.Policy
		}
	}
	result := assess.Classify(merged)
	phases := plan.Build(merged, result)
	org := readOrgInputs(orgPath)
	rep := report.Build(merged, result, phases, cost.Annual(org))
	raw, err := report.ToJSON(rep)
	if err != nil {
		return err
	}
	if err := os.WriteFile(out, raw, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s (%d ready now, %d need remediation, %d exceptions, %d unknown)\n",
		out, result.ReadyNow, result.NeedsRemediation, result.Exceptions, result.Unknown)
	base := strings.TrimSuffix(out, ".json")
	for _, f := range strings.Split(format, ",") {
		switch strings.TrimSpace(f) {
		case "md":
			p := base + ".md"
			if err := os.WriteFile(p, []byte(report.ToMarkdown(rep)), 0o644); err != nil {
				return err
			}
			fmt.Printf("wrote %s\n", p)
		case "html":
			p := base + ".html"
			html, err := report.ToHTML(rep)
			if err != nil {
				return err
			}
			if err := os.WriteFile(p, []byte(html), 0o644); err != nil {
				return err
			}
			fmt.Printf("wrote %s (open in a browser; Print → Save as PDF)\n", p)
		case "":
			// JSON only.
		default:
			return fmt.Errorf("unknown format %q (want md and/or html)", f)
		}
	}
	return nil
}

func loadInventory(path string) (*model.Inventory, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var inv model.Inventory
	if err := json.Unmarshal(raw, &inv); err != nil {
		return nil, fmt.Errorf("bad inventory %s: %w", path, err)
	}
	return &inv, nil
}

func writeInventory(out string, inv *model.Inventory) error {
	if out == "" {
		return fmt.Errorf("--out is required")
	}
	raw, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(out, raw, 0o644)
}

// readOrgInputs parses a minimal org.yaml (key: value floats). Missing file
// or keys yield zero inputs, which the cost package renders as "not provided".
func readOrgInputs(path string) cost.Inputs {
	var in cost.Inputs
	if path == "" {
		return in
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return in
	}
	for _, line := range strings.Split(string(raw), "\n") {
		kv := strings.SplitN(strings.TrimSpace(line), ":", 2)
		if len(kv) != 2 {
			continue
		}
		var v float64
		fmt.Sscanf(strings.TrimSpace(kv[1]), "%f", &v)
		switch strings.TrimSpace(kv[0]) {
		case "resets_per_month":
			in.ResetsPerMonth = v
		case "minutes_per_reset":
			in.MinutesPerReset = v
		case "hourly_rate":
			in.HourlyRate = v
		case "estimated_breach_cost":
			in.EstimatedBreach = v
		}
	}
	return in
}

// flagSet parses --key value / --key=value args without external deps.
func flagSet(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(args); i++ {
		a := strings.TrimPrefix(args[i], "--")
		if strings.Contains(a, "=") {
			kv := strings.SplitN(a, "=", 2)
			m[kv[0]] = kv[1]
			continue
		}
		if i+1 < len(args) && !strings.HasPrefix(args[i+1], "--") {
			m[a] = args[i+1]
			i++
		} else {
			m[a] = "true"
		}
	}
	return m
}

func flagVal(m map[string]string, k string) string { return m[k] }
