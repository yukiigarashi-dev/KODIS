// Package evaluate turns a snapshot into findings using deterministic
// rules. It has no I/O and makes no changes.
package evaluate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// Rule IDs.
const (
	// RuleMFAPolicyDisabled: a policy that requires MFA is disabled.
	RuleMFAPolicyDisabled = "ca.mfa-policy-disabled"
	// RuleBreakGlassNotExcluded: a policy does not exclude every
	// break-glass account, so enabling or enforcing it risks lockout.
	RuleBreakGlassNotExcluded = "ca.breakglass-not-excluded"
)

// Config is operator-supplied evaluation configuration.
type Config struct {
	BreakGlassUserIDs []string
}

// Evaluate applies every rule to every policy. Findings are sorted by ID
// so the output does not depend on snapshot order.
func Evaluate(cfg Config, s model.Snapshot) ([]model.Finding, error) {
	if len(cfg.BreakGlassUserIDs) == 0 {
		return nil, fmt.Errorf("evaluate: no break-glass accounts configured")
	}
	for i, id := range cfg.BreakGlassUserIDs {
		if id == "" || id == model.AllUsers {
			return nil, fmt.Errorf("evaluate: breakGlassUserIDs[%d] %q is not a user id", i, id)
		}
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("evaluate: invalid snapshot: %w", err)
	}
	var out []model.Finding
	for _, p := range s.Policies {
		if p.State == model.CAStateDisabled &&
			slices.Contains(p.GrantControls, model.GrantMFA) &&
			!slices.Contains(p.GrantControls, model.GrantBlock) {
			out = append(out, finding(RuleMFAPolicyDisabled, model.SeverityHigh, p.ID,
				fmt.Sprintf("Conditional Access policy %s requires MFA but is disabled", p.ID)))
		}
		var missing []string
		for _, id := range cfg.BreakGlassUserIDs {
			if !slices.Contains(p.ExcludeUsers, id) {
				missing = append(missing, id)
			}
		}
		if len(missing) > 0 {
			out = append(out, finding(RuleBreakGlassNotExcluded, model.SeverityHigh, p.ID,
				fmt.Sprintf("Conditional Access policy %s does not exclude break-glass accounts: %s", p.ID, strings.Join(missing, ", "))))
		}
	}
	for _, f := range out {
		if err := f.Validate(); err != nil {
			return nil, fmt.Errorf("evaluate: rule produced invalid finding: %w", err)
		}
	}
	slices.SortFunc(out, func(a, b model.Finding) int { return strings.Compare(a.ID, b.ID) })
	return out, nil
}

// finding builds a Finding whose ID is derived from the rule and resource,
// so the same condition always yields the same ID.
func finding(rule string, sev model.Severity, policyID, summary string) model.Finding {
	res := model.ResourceRef{Kind: model.KindConditionalAccessPolicy, ID: policyID}
	sum := sha256.Sum256([]byte(rule + "\x00" + string(res.Kind) + "\x00" + res.ID))
	return model.Finding{
		ID:       "finding-" + hex.EncodeToString(sum[:8]),
		RuleID:   rule,
		Severity: sev,
		Resource: res,
		Summary:  summary,
	}
}
