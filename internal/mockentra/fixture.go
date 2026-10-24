package mockentra

import (
	"fmt"
	"os"
	"strings"

	"github.com/yukiigarashi-dev/kodis/internal/model"
)

// MaxFixtureBytes bounds the size of a fixture file.
const MaxFixtureBytes = 4 << 20

// generatedVersionPrefix marks versions issued by the mock. Fixtures may
// not use it, so an issued version never equals a fixture version.
const generatedVersionPrefix = "gen-"

// User is a synthetic directory user.
type User struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// Role is a synthetic directory role.
type Role struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

// Fixture is the initial state of a simulated tenant. All data must be
// synthetic.
type Fixture struct {
	TenantID string                          `json:"tenantId"`
	Users    []User                          `json:"users"`
	Roles    []Role                          `json:"roles"`
	Policies []model.ConditionalAccessPolicy `json:"policies"`
}

// Snapshot returns the policies as a model.Snapshot.
func (f Fixture) Snapshot() model.Snapshot {
	s := model.Snapshot{TenantID: f.TenantID}
	for _, p := range f.Policies {
		s.Policies = append(s.Policies, clonePolicy(p))
	}
	return s
}

// Validate checks the fixture, including that every user and role a
// policy refers to exists. Dangling references would make break-glass
// tests pass vacuously.
func (f Fixture) Validate() error {
	if err := f.Snapshot().Validate(); err != nil {
		return err
	}
	users, err := ids("users", f.Users, func(u User) string { return u.ID })
	if err != nil {
		return err
	}
	roles, err := ids("roles", f.Roles, func(r Role) string { return r.ID })
	if err != nil {
		return err
	}
	for i, p := range f.Policies {
		field := fmt.Sprintf("policies[%d]", i)
		if strings.HasPrefix(p.Version, generatedVersionPrefix) {
			return fmt.Errorf("%s.version: prefix %q is reserved for the mock", field, generatedVersionPrefix)
		}
		for _, u := range p.IncludeUsers {
			if u != model.AllUsers && !users[u] {
				return fmt.Errorf("%s.includeUsers: unknown user %q", field, u)
			}
		}
		for _, u := range p.ExcludeUsers {
			if !users[u] {
				return fmt.Errorf("%s.excludeUsers: unknown user %q", field, u)
			}
		}
		for _, r := range p.IncludeRoles {
			if !roles[r] {
				return fmt.Errorf("%s.includeRoles: unknown role %q", field, r)
			}
		}
	}
	return nil
}

func ids[T any](field string, items []T, id func(T) string) (map[string]bool, error) {
	seen := make(map[string]bool, len(items))
	for i, it := range items {
		v := id(it)
		if v == "" || v == model.AllUsers || strings.ContainsAny(v, " \t\n") {
			return nil, fmt.Errorf("%s[%d].id: invalid id %q", field, i, v)
		}
		if seen[v] {
			return nil, fmt.Errorf("%s[%d].id: duplicate id %q", field, i, v)
		}
		seen[v] = true
	}
	return seen, nil
}

// DecodeFixture strictly decodes and validates a fixture.
func DecodeFixture(data []byte) (Fixture, error) {
	var f Fixture
	if err := model.DecodeStrict(data, MaxFixtureBytes, &f); err != nil {
		return Fixture{}, err
	}
	if err := f.Validate(); err != nil {
		return Fixture{}, err
	}
	return f, nil
}

// LoadFixture reads and decodes a fixture file.
func LoadFixture(path string) (Fixture, error) {
	file, err := os.Open(path)
	if err != nil {
		return Fixture{}, err
	}
	defer file.Close()
	data, err := model.ReadLimited(file, MaxFixtureBytes)
	if err != nil {
		return Fixture{}, fmt.Errorf("%s: %w", path, err)
	}
	f, err := DecodeFixture(data)
	if err != nil {
		return Fixture{}, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}
