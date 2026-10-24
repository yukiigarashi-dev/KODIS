package inspect

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yukiigarashi-dev/kodis/internal/mockentra"
	"github.com/yukiigarashi-dev/kodis/internal/model"
)

const tenantID = "tenant-contoso.example.test"

type fakeReader struct {
	snap model.Snapshot
	err  error
}

func (f fakeReader) ReadSnapshot(context.Context) (model.Snapshot, error) { return f.snap, f.err }
func (f fakeReader) ReadConditionalAccessPolicy(context.Context, string) (model.ConditionalAccessPolicy, error) {
	return model.ConditionalAccessPolicy{}, errors.New("not used")
}

func TestInspectBaseline(t *testing.T) {
	f, err := mockentra.LoadFixture(filepath.Join("..", "..", "testdata", "scenarios", "baseline", "tenant.json"))
	if err != nil {
		t.Fatal(err)
	}
	tn, err := mockentra.New(f)
	if err != nil {
		t.Fatal(err)
	}
	s, err := Inspect(context.Background(), tn.Reader(), tenantID)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Policies) != len(f.Policies) {
		t.Fatalf("got %d policies, want %d", len(s.Policies), len(f.Policies))
	}
}

func TestInspectRejects(t *testing.T) {
	good := model.Snapshot{TenantID: tenantID}
	dup := model.ConditionalAccessPolicy{ID: "p1", Version: "v1", State: model.CAStateDisabled}
	sentinel := errors.New("read failed")
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()

	cases := map[string]struct {
		ctx    context.Context
		r      fakeReader
		tenant string
		is     error
	}{
		"read error":         {context.Background(), fakeReader{err: sentinel}, tenantID, sentinel},
		"other tenant":       {context.Background(), fakeReader{snap: good}, "tenant-other.example.test", nil},
		"empty tenant":       {context.Background(), fakeReader{snap: model.Snapshot{}}, "", nil},
		"duplicate policies": {context.Background(), fakeReader{snap: model.Snapshot{TenantID: tenantID, Policies: []model.ConditionalAccessPolicy{dup, dup}}}, tenantID, nil},
		"unknown state":      {context.Background(), fakeReader{snap: model.Snapshot{TenantID: tenantID, Policies: []model.ConditionalAccessPolicy{{ID: "p1", Version: "v1", State: "paused"}}}}, tenantID, nil},
		"cancelled":          {cancelled, fakeReader{err: context.Canceled}, tenantID, context.Canceled},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Inspect(c.ctx, c.r, c.tenant)
			if err == nil {
				t.Fatal("expected error")
			}
			if c.is != nil && !errors.Is(err, c.is) {
				t.Fatalf("got %v, want wrapping %v", err, c.is)
			}
		})
	}
	if _, err := Inspect(context.Background(), nil, tenantID); err == nil {
		t.Fatal("nil reader accepted")
	}
}
