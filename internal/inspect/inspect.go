// Package inspect collects tenant state through a read-only interface.
package inspect

import (
	"context"
	"fmt"

	"github.com/yukiigarashi-dev/kodis/internal/entra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// Inspect reads a snapshot and rejects it unless it is valid and belongs
// to the expected tenant.
func Inspect(ctx context.Context, r entra.Reader, tenantID string) (model.Snapshot, error) {
	if r == nil {
		return model.Snapshot{}, fmt.Errorf("inspect: nil reader")
	}
	s, err := r.ReadSnapshot(ctx)
	if err != nil {
		return model.Snapshot{}, fmt.Errorf("inspect: read snapshot: %w", err)
	}
	if err := s.Validate(); err != nil {
		return model.Snapshot{}, fmt.Errorf("inspect: invalid snapshot: %w", err)
	}
	if s.TenantID != tenantID {
		return model.Snapshot{}, fmt.Errorf("inspect: snapshot is for tenant %q, expected %q", s.TenantID, tenantID)
	}
	return s, nil
}
