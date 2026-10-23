// Package model defines the data exchanged between KODIS stages and the
// canonical hash that binds an approval to an exact plan.
//
// A Plan is untrusted input. Validate only checks structure; whether an
// action is permitted is decided by internal/policy and re-checked by
// internal/execute.
package model

import (
	"fmt"
	"slices"
	"time"
)

// PlanSchemaV1 is the only accepted plan schema.
const PlanSchemaV1 = "kodis.plan/v1"

// MaxActions bounds the size of a single plan.
const MaxActions = 32

// Operation names a state change. Unknown operations are rejected here and,
// independently, by the policy engine and executor.
type Operation string

const (
	// OpSetConditionalAccessState changes a Conditional Access policy's state.
	OpSetConditionalAccessState Operation = "conditionalAccess.setState"
)

var knownOperations = []Operation{OpSetConditionalAccessState}

// ResourceKind names the type of a directory object.
type ResourceKind string

const (
	KindConditionalAccessPolicy ResourceKind = "conditionalAccessPolicy"
)

var knownKinds = []ResourceKind{KindConditionalAccessPolicy}

// Severity of a finding.
type Severity string

const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var knownSeverities = []Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}

// ResourceRef identifies a directory object.
type ResourceRef struct {
	Kind ResourceKind `json:"kind"`
	ID   string       `json:"id"`
}

// Finding is the result of a deterministic evaluation rule.
type Finding struct {
	ID       string      `json:"id"`
	RuleID   string      `json:"ruleId"`
	Severity Severity    `json:"severity"`
	Resource ResourceRef `json:"resource"`
	Summary  string      `json:"summary"`
}

// Action is a single proposed state change. ExpectedVersion and
// ExpectedState are the preconditions observed at inspection time; the
// executor writes only if both still hold.
type Action struct {
	ID              string      `json:"id"`
	Operation       Operation   `json:"operation"`
	Target          ResourceRef `json:"target"`
	ExpectedVersion string      `json:"expectedVersion"`
	ExpectedState   string      `json:"expectedState"`
	DesiredState    string      `json:"desiredState"`
}

// Plan is an ordered list of actions justified by findings.
//
// Field order is part of the canonical encoding (see Hash). Reordering or
// renaming fields changes every plan hash and must bump PlanSchemaV1.
type Plan struct {
	Schema     string    `json:"schema"`
	ID         string    `json:"id"`
	TenantID   string    `json:"tenantId"`
	CreatedAt  time.Time `json:"createdAt"`
	FindingIDs []string  `json:"findingIds"`
	Actions    []Action  `json:"actions"`
}

const maxTokenLen = 128
const maxSummaryLen = 1024

// validToken accepts 1..128 bytes of [A-Za-z0-9._:-]. Restricting the
// alphabet avoids Unicode confusables and normalization ambiguity in
// anything that is hashed or compared.
func validToken(s string) bool {
	if len(s) == 0 || len(s) > maxTokenLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '.', c == '_', c == ':', c == '-':
		default:
			return false
		}
	}
	return true
}

func checkToken(field, v string) error {
	if !validToken(v) {
		return invalid(field, "must be 1-%d chars of [A-Za-z0-9._:-]", maxTokenLen)
	}
	return nil
}

// Validate checks a ResourceRef.
func (r ResourceRef) Validate(field string) error {
	if !slices.Contains(knownKinds, r.Kind) {
		return invalid(field+".kind", "unknown kind %q", r.Kind)
	}
	return checkToken(field+".id", r.ID)
}

// Validate checks a Finding.
func (f Finding) Validate() error {
	if err := checkToken("id", f.ID); err != nil {
		return err
	}
	if err := checkToken("ruleId", f.RuleID); err != nil {
		return err
	}
	if !slices.Contains(knownSeverities, f.Severity) {
		return invalid("severity", "unknown severity %q", f.Severity)
	}
	if err := f.Resource.Validate("resource"); err != nil {
		return err
	}
	if f.Summary == "" || len(f.Summary) > maxSummaryLen {
		return invalid("summary", "must be 1-%d bytes", maxSummaryLen)
	}
	return nil
}

// Validate checks an Action's structure.
func (a Action) Validate(field string) error {
	if err := checkToken(field+".id", a.ID); err != nil {
		return err
	}
	if !slices.Contains(knownOperations, a.Operation) {
		return invalid(field+".operation", "unknown operation %q", a.Operation)
	}
	if err := a.Target.Validate(field + ".target"); err != nil {
		return err
	}
	if err := checkToken(field+".expectedVersion", a.ExpectedVersion); err != nil {
		return err
	}
	if err := checkToken(field+".expectedState", a.ExpectedState); err != nil {
		return err
	}
	if err := checkToken(field+".desiredState", a.DesiredState); err != nil {
		return err
	}
	if a.ExpectedState == a.DesiredState {
		return invalid(field+".desiredState", "must differ from expectedState")
	}
	return nil
}

// Validate checks a Plan's structure. It does not decide whether the plan
// is permitted.
func (p Plan) Validate() error {
	if p.Schema != PlanSchemaV1 {
		return &Error{Code: CodeUnsupportedSchema, Field: "schema", Msg: fmt.Sprintf("want %q, got %q", PlanSchemaV1, p.Schema)}
	}
	if err := checkToken("id", p.ID); err != nil {
		return err
	}
	if err := checkToken("tenantId", p.TenantID); err != nil {
		return err
	}
	// Canonical timestamps are UTC and non-zero so that equal instants
	// always encode to the same bytes.
	if p.CreatedAt.IsZero() {
		return invalid("createdAt", "must be set")
	}
	if p.CreatedAt.Location() != time.UTC {
		return invalid("createdAt", "must be UTC")
	}
	if len(p.FindingIDs) == 0 {
		return invalid("findingIds", "must not be empty")
	}
	for i, id := range p.FindingIDs {
		f := fmt.Sprintf("findingIds[%d]", i)
		if err := checkToken(f, id); err != nil {
			return err
		}
		if i > 0 && p.FindingIDs[i-1] >= id {
			return invalid(f, "must be strictly ascending (sorted, no duplicates)")
		}
	}
	if len(p.Actions) == 0 || len(p.Actions) > MaxActions {
		return invalid("actions", "must contain 1-%d actions", MaxActions)
	}
	seen := make(map[string]bool, len(p.Actions))
	for i, a := range p.Actions {
		f := fmt.Sprintf("actions[%d]", i)
		if err := a.Validate(f); err != nil {
			return err
		}
		if seen[a.ID] {
			return invalid(f+".id", "duplicate action id %q", a.ID)
		}
		seen[a.ID] = true
	}
	return nil
}
