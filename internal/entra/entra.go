// Package entra declares the interfaces to a (simulated) Microsoft Entra
// tenant. There is no implementation that talks to a real tenant.
//
// Reader and Writer are deliberately separate: only internal/execute may
// hold a Writer (enforced by internal/archtest), and verification uses a
// Reader of its own.
package entra

import (
	"context"
	"errors"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

var (
	// ErrNotFound means the object does not exist.
	ErrNotFound = errors.New("entra: not found")
	// ErrVersionConflict means the object changed since expectedVersion.
	ErrVersionConflict = errors.New("entra: version conflict")
)

// Reader reads tenant state.
type Reader interface {
	ReadSnapshot(ctx context.Context) (model.Snapshot, error)
	ReadConditionalAccessPolicy(ctx context.Context, id string) (model.ConditionalAccessPolicy, error)
}

// Writer changes tenant state. Every write is a compare-and-swap on the
// object's version.
type Writer interface {
	// SetConditionalAccessState sets the policy's state only if its current
	// version equals expectedVersion, and returns the new version. A
	// successful return does not prove the change is visible; callers
	// verify through a Reader.
	SetConditionalAccessState(ctx context.Context, id, expectedVersion string, state model.CAState) (newVersion string, err error)
}
