package model

import (
	"strings"
	"testing"
)

func validSnapshot() Snapshot {
	return Snapshot{
		TenantID: "tenant-contoso.example.test",
		Policies: []ConditionalAccessPolicy{{
			ID:            "ca-require-mfa-admins",
			Version:       "v7",
			DisplayName:   "Require MFA for administrators",
			State:         CAStateDisabled,
			IncludeUsers:  []string{AllUsers},
			ExcludeUsers:  []string{"user-breakglass-01"},
			IncludeRoles:  []string{"role-global-admin"},
			GrantControls: []string{GrantMFA},
		}},
	}
}

func TestSnapshotValid(t *testing.T) {
	s := validSnapshot()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Policy("ca-require-mfa-admins"); !ok {
		t.Fatal("lookup failed")
	}
	if _, ok := s.Policy("missing"); ok {
		t.Fatal("lookup of missing policy succeeded")
	}
}

func TestSnapshotValidateRejects(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"empty tenant":        func(s *Snapshot) { s.TenantID = "" },
		"duplicate policy":    func(s *Snapshot) { s.Policies = append(s.Policies, s.Policies[0]) },
		"empty policy id":     func(s *Snapshot) { s.Policies[0].ID = "" },
		"empty version":       func(s *Snapshot) { s.Policies[0].Version = "" },
		"unknown state":       func(s *Snapshot) { s.Policies[0].State = "Enabled" },
		"empty state":         func(s *Snapshot) { s.Policies[0].State = "" },
		"bad include user":    func(s *Snapshot) { s.Policies[0].IncludeUsers = []string{"a b"} },
		"bad exclude user":    func(s *Snapshot) { s.Policies[0].ExcludeUsers = []string{""} },
		"bad role":            func(s *Snapshot) { s.Policies[0].IncludeRoles = []string{"röle"} },
		"bad grant":           func(s *Snapshot) { s.Policies[0].GrantControls = []string{"mfa;block"} },
		"display name long":   func(s *Snapshot) { s.Policies[0].DisplayName = strings.Repeat("a", maxSummaryLen+1) },
		"non-ascii lookalike": func(s *Snapshot) { s.Policies[0].ExcludeUsers = []string{"user-breakglass-0１"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := validSnapshot()
			mutate(&s)
			if err := s.Validate(); err == nil {
				t.Fatal("expected rejection")
			}
		})
	}
}
