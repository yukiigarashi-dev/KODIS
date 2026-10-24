// Package mockentra is an in-memory simulated Entra tenant for tests and
// the CLI. It never connects to anything.
//
// The mock is not a safety layer: like the real service it accepts any
// valid state change with a matching version. Safety must come from
// internal/policy and internal/execute, so tests against the mock cannot
// pass merely because the mock refused something.
//
// Only cmd/kodis may import this package outside tests (internal/archtest).
package mockentra

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/yukiigarashi-dev/kodis/internal/entra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// Fault is a failure injected into the next write.
type Fault int

const (
	// FaultNone performs the write normally.
	FaultNone Fault = iota
	// FaultWriteError fails the write without applying it.
	FaultWriteError
	// FaultDropWrite reports success with a new version but applies nothing.
	FaultDropWrite
	// FaultConcurrentModify changes the target out of band just before the
	// compare-and-swap, so the write fails with a version conflict.
	FaultConcurrentModify
	// FaultStaleRead applies the write, but readers keep returning the
	// state from before it until ClearStaleReads is called.
	FaultStaleRead
)

// ErrInjected is returned by FaultWriteError.
var ErrInjected = errors.New("mockentra: injected write failure")

// WriteRecord is one successful, applied write.
type WriteRecord struct {
	PolicyID   string
	OldVersion string
	NewVersion string
	OldState   model.CAState
	NewState   model.CAState
}

// Tenant is a simulated tenant. It is safe for concurrent use.
type Tenant struct {
	mu       sync.Mutex
	tenantID string
	order    []string
	policies map[string]model.ConditionalAccessPolicy
	seq      int
	faults   []Fault
	stale    *model.Snapshot
	writes   []WriteRecord
}

// New creates a tenant from a validated copy of f.
func New(f Fixture) (*Tenant, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	t := &Tenant{tenantID: f.TenantID, policies: map[string]model.ConditionalAccessPolicy{}}
	for _, p := range f.Policies {
		t.order = append(t.order, p.ID)
		t.policies[p.ID] = clonePolicy(p)
	}
	return t, nil
}

// Reader returns a read-only view.
func (t *Tenant) Reader() entra.Reader { return reader{t} }

// Writer returns a write view.
func (t *Tenant) Writer() entra.Writer { return writer{t} }

// InjectFault queues a fault for the next write. Faults are consumed in
// order, one per write call.
func (t *Tenant) InjectFault(f Fault) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.faults = append(t.faults, f)
}

// ClearStaleReads makes readers see current state again.
func (t *Tenant) ClearStaleReads() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stale = nil
}

// Modify changes a policy out of band, as another administrator would,
// and issues a new version.
func (t *Tenant) Modify(id string, fn func(*model.ConditionalAccessPolicy)) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	cur, ok := t.policies[id]
	if !ok {
		return entra.ErrNotFound
	}
	// Mutate a copy so a rejected change leaves the stored policy intact.
	p := clonePolicy(cur)
	fn(&p)
	p.ID = id
	p.Version = t.nextVersion()
	if err := p.Validate("policy"); err != nil {
		return err
	}
	t.policies[id] = clonePolicy(p)
	return nil
}

// Writes returns the applied writes in order.
func (t *Tenant) Writes() []WriteRecord {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.writes)
}

func (t *Tenant) nextVersion() string {
	t.seq++
	return fmt.Sprintf("%s%d", generatedVersionPrefix, t.seq)
}

func (t *Tenant) snapshotLocked() model.Snapshot {
	s := model.Snapshot{TenantID: t.tenantID}
	for _, id := range t.order {
		s.Policies = append(s.Policies, clonePolicy(t.policies[id]))
	}
	return s
}

func clonePolicy(p model.ConditionalAccessPolicy) model.ConditionalAccessPolicy {
	p.IncludeUsers = slices.Clone(p.IncludeUsers)
	p.ExcludeUsers = slices.Clone(p.ExcludeUsers)
	p.IncludeRoles = slices.Clone(p.IncludeRoles)
	p.GrantControls = slices.Clone(p.GrantControls)
	return p
}

func cloneSnapshot(s model.Snapshot) model.Snapshot {
	out := model.Snapshot{TenantID: s.TenantID}
	for _, p := range s.Policies {
		out.Policies = append(out.Policies, clonePolicy(p))
	}
	return out
}

type reader struct{ t *Tenant }

func (r reader) ReadSnapshot(ctx context.Context) (model.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return model.Snapshot{}, err
	}
	r.t.mu.Lock()
	defer r.t.mu.Unlock()
	if r.t.stale != nil {
		return cloneSnapshot(*r.t.stale), nil
	}
	return r.t.snapshotLocked(), nil
}

func (r reader) ReadConditionalAccessPolicy(ctx context.Context, id string) (model.ConditionalAccessPolicy, error) {
	s, err := r.ReadSnapshot(ctx)
	if err != nil {
		return model.ConditionalAccessPolicy{}, err
	}
	p, ok := s.Policy(id)
	if !ok {
		return model.ConditionalAccessPolicy{}, entra.ErrNotFound
	}
	return p, nil
}

type writer struct{ t *Tenant }

func (w writer) SetConditionalAccessState(ctx context.Context, id, expectedVersion string, state model.CAState) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	t := w.t
	t.mu.Lock()
	defer t.mu.Unlock()

	fault := FaultNone
	if len(t.faults) > 0 {
		fault = t.faults[0]
		t.faults = t.faults[1:]
	}

	p, ok := t.policies[id]
	if !ok {
		return "", entra.ErrNotFound
	}
	switch fault {
	case FaultWriteError:
		return "", ErrInjected
	case FaultConcurrentModify:
		p.Version = t.nextVersion()
		t.policies[id] = p
	}
	if p.Version != expectedVersion {
		return "", fmt.Errorf("%w: %s is at %s, expected %s", entra.ErrVersionConflict, id, p.Version, expectedVersion)
	}
	next := p
	next.State = state
	next.Version = t.nextVersion()
	if err := next.Validate("policy"); err != nil {
		return "", err
	}
	if fault == FaultDropWrite {
		return next.Version, nil
	}
	if fault == FaultStaleRead && t.stale == nil {
		s := t.snapshotLocked()
		t.stale = &s
	}
	t.policies[id] = next
	t.writes = append(t.writes, WriteRecord{PolicyID: id, OldVersion: p.Version, NewVersion: next.Version, OldState: p.State, NewState: state})
	return next.Version, nil
}
