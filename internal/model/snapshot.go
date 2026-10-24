package model

import (
	"fmt"
	"slices"
)

// CAState is a Conditional Access policy state.
type CAState string

const (
	CAStateEnabled    CAState = "enabled"
	CAStateDisabled   CAState = "disabled"
	CAStateReportOnly CAState = "enabledForReportingButNotEnforced"
)

var knownCAStates = []CAState{CAStateEnabled, CAStateDisabled, CAStateReportOnly}

// Grant controls relevant to policy decisions.
const (
	GrantMFA   = "mfa"
	GrantBlock = "block"
)

// AllUsers is the IncludeUsers value that targets every user.
const AllUsers = "All"

// ConditionalAccessPolicy is the observed state of one policy, reduced to
// the fields KODIS reasons about.
type ConditionalAccessPolicy struct {
	ID            string   `json:"id"`
	Version       string   `json:"version"`
	DisplayName   string   `json:"displayName"`
	State         CAState  `json:"state"`
	IncludeUsers  []string `json:"includeUsers"`
	ExcludeUsers  []string `json:"excludeUsers"`
	IncludeRoles  []string `json:"includeRoles"`
	GrantControls []string `json:"grantControls"`
}

// Snapshot is the observed tenant state an evaluation is based on.
type Snapshot struct {
	TenantID string                    `json:"tenantId"`
	Policies []ConditionalAccessPolicy `json:"policies"`
}

func checkTokens(field string, vs []string) error {
	for i, v := range vs {
		if err := checkToken(fmt.Sprintf("%s[%d]", field, i), v); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks one observed policy.
func (c ConditionalAccessPolicy) Validate(field string) error {
	if err := checkToken(field+".id", c.ID); err != nil {
		return err
	}
	if err := checkToken(field+".version", c.Version); err != nil {
		return err
	}
	if len(c.DisplayName) > maxSummaryLen {
		return invalid(field+".displayName", "must be at most %d bytes", maxSummaryLen)
	}
	if !slices.Contains(knownCAStates, c.State) {
		return invalid(field+".state", "unknown state %q", c.State)
	}
	for name, vs := range map[string][]string{
		"includeUsers":  c.IncludeUsers,
		"excludeUsers":  c.ExcludeUsers,
		"includeRoles":  c.IncludeRoles,
		"grantControls": c.GrantControls,
	} {
		if err := checkTokens(field+"."+name, vs); err != nil {
			return err
		}
	}
	return nil
}

// Validate checks the snapshot. Duplicate policy IDs are rejected so that a
// lookup by ID is unambiguous.
func (s Snapshot) Validate() error {
	if err := checkToken("tenantId", s.TenantID); err != nil {
		return err
	}
	seen := make(map[string]bool, len(s.Policies))
	for i, p := range s.Policies {
		f := fmt.Sprintf("policies[%d]", i)
		if err := p.Validate(f); err != nil {
			return err
		}
		if seen[p.ID] {
			return invalid(f+".id", "duplicate policy id %q", p.ID)
		}
		seen[p.ID] = true
	}
	return nil
}

// Policy returns the policy with the given ID.
func (s Snapshot) Policy(id string) (ConditionalAccessPolicy, bool) {
	for _, p := range s.Policies {
		if p.ID == id {
			return p, true
		}
	}
	return ConditionalAccessPolicy{}, false
}
