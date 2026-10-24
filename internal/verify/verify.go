// Package verify checks, after execution, that the tenant is actually in
// the state an approved plan asked for.
//
// It deliberately does not consume executor results (internal/archtest
// forbids importing internal/execute): it re-reads every target through
// its own entra.Reader and compares against the plan.
//
// Limitation: against the mock tenant the Reader is a different code path
// over the same in-memory store, so this is independent of the executor's
// logic but not of the store itself.
package verify

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/yukiigarashi-dev/kodis/internal/entra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// Config is the post-condition configuration.
type Config struct {
	// BreakGlassUserIDs must still be excluded from every target.
	BreakGlassUserIDs []string
}

// Check is the result for one action.
type Check struct {
	ActionID        string        `json:"actionId"`
	PolicyID        string        `json:"policyId"`
	Expected        model.CAState `json:"expected"`
	Observed        model.CAState `json:"observed"`
	ObservedVersion string        `json:"observedVersion"`
	Problems        []string      `json:"problems"`
}

// OK reports whether the action's post-conditions hold.
func (c Check) OK() bool { return len(c.Problems) == 0 }

// Report is the result for a plan. The zero value is not verified.
type Report struct {
	PlanHash model.Digest `json:"planHash"`
	Checks   []Check      `json:"checks"`
	verified bool
}

// Verified reports whether every action's post-conditions hold.
func (r Report) Verified() bool { return r.verified }

// Verify re-reads tenant state and checks, for each action, that the
// target is in the desired state, that its version moved past the one the
// plan expected, and that every break-glass account is still excluded.
// The snapshot must be valid and belong to the plan's tenant. An error
// means verification could not be performed; a Report with Verified()
// false means it was performed and failed.
func Verify(ctx context.Context, r entra.Reader, cfg Config, p model.Plan) (Report, error) {
	if r == nil {
		return Report{}, errors.New("verify: nil reader")
	}
	if len(cfg.BreakGlassUserIDs) == 0 {
		return Report{}, errors.New("verify: no break-glass accounts configured")
	}
	h, err := model.HashPlan(p)
	if err != nil {
		return Report{}, fmt.Errorf("verify: %w", err)
	}
	snap, err := r.ReadSnapshot(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("verify: read snapshot: %w", err)
	}
	if err := snap.Validate(); err != nil {
		return Report{}, fmt.Errorf("verify: invalid snapshot: %w", err)
	}
	if snap.TenantID != p.TenantID {
		return Report{}, fmt.Errorf("verify: reader is for tenant %q, plan is for %q", snap.TenantID, p.TenantID)
	}
	rep := Report{PlanHash: h}
	all := true
	for _, a := range p.Actions {
		c := Check{ActionID: a.ID, PolicyID: a.Target.ID, Expected: model.CAState(a.DesiredState)}
		if cur, ok := snap.Policy(a.Target.ID); !ok {
			c.Problems = append(c.Problems, "target no longer exists")
		} else {
			c.Observed, c.ObservedVersion = cur.State, cur.Version
			c.Problems = append(c.Problems, problems(cfg, a, cur)...)
		}
		all = all && c.OK()
		rep.Checks = append(rep.Checks, c)
	}
	rep.verified = all && len(rep.Checks) > 0
	return rep, nil
}

func problems(cfg Config, a model.Action, cur model.ConditionalAccessPolicy) []string {
	var out []string
	if string(cur.State) != a.DesiredState {
		out = append(out, fmt.Sprintf("state is %q, want %q", cur.State, a.DesiredState))
	}
	if cur.Version == a.ExpectedVersion {
		out = append(out, fmt.Sprintf("version is still %q; no write is visible", cur.Version))
	}
	for _, id := range cfg.BreakGlassUserIDs {
		if !slices.Contains(cur.ExcludeUsers, id) {
			out = append(out, fmt.Sprintf("break-glass user %q is not excluded", id))
		}
	}
	return out
}
