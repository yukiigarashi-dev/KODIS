package archtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const mod = "example.test/kodis"

func TestCheckBoundariesDetectsViolations(t *testing.T) {
	cases := []struct {
		name string
		pkg  Package
		want int
	}{
		{"execute imports plan transitively", Package{ImportPath: mod + "/internal/execute", Deps: []string{mod + "/internal/helper", mod + "/internal/plan"}}, 1},
		{"execute subpackage imports inspect", Package{ImportPath: mod + "/internal/execute/cas", Deps: []string{mod + "/internal/inspect"}}, 1},
		{"policy imports os directly", Package{ImportPath: mod + "/internal/policy", Imports: []string{"os"}}, 1},
		{"policy imports net/http directly", Package{ImportPath: mod + "/internal/policy", Imports: []string{"net/http"}}, 1},
		{"policy imports entra transitively", Package{ImportPath: mod + "/internal/policy", Deps: []string{mod + "/internal/entra"}}, 1},
		{"verify imports execute", Package{ImportPath: mod + "/internal/verify", Deps: []string{mod + "/internal/execute"}}, 1},
		{"plan imports approve", Package{ImportPath: mod + "/internal/plan", Deps: []string{mod + "/internal/approve"}}, 1},
		{"policy uses fmt (os only transitive)", Package{ImportPath: mod + "/internal/policy", Imports: []string{"fmt"}, Deps: []string{"fmt", "os"}}, 0},
		{"executor imports model", Package{ImportPath: mod + "/internal/execute", Deps: []string{mod + "/internal/model"}}, 0},
		{"prefix is not a subpackage", Package{ImportPath: mod + "/internal/executeutil", Deps: []string{mod + "/internal/plan"}}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CheckBoundaries(mod, []Package{c.pkg}, Rules)
			if len(got) != c.want {
				t.Fatalf("got %d violations %v, want %d", len(got), got, c.want)
			}
		})
	}
}

func TestCheckImporters(t *testing.T) {
	cases := []struct {
		name string
		pkg  Package
		want int
	}{
		{"verify imports mock", Package{ImportPath: mod + "/internal/verify", Deps: []string{mod + "/internal/mockentra"}}, 1},
		{"new package imports mock transitively", Package{ImportPath: mod + "/internal/newpkg", Deps: []string{mod + "/internal/helper", mod + "/internal/mockentra"}}, 1},
		{"execute imports mock subpackage", Package{ImportPath: mod + "/internal/execute", Deps: []string{mod + "/internal/mockentra/faults"}}, 1},
		{"cli imports mock", Package{ImportPath: mod + "/cmd/kodis", Deps: []string{mod + "/internal/mockentra"}}, 0},
		{"mock itself", Package{ImportPath: mod + "/internal/mockentra", Deps: []string{mod + "/internal/entra"}}, 0},
		{"prefix is not the mock", Package{ImportPath: mod + "/internal/verify", Deps: []string{mod + "/internal/mockentrax"}}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := CheckImporters(mod, []Package{c.pkg}, ImportRules); len(got) != c.want {
				t.Fatalf("got %v, want %d violations", got, c.want)
			}
		})
	}
}

func TestCheckStdlibOnly(t *testing.T) {
	pkgs := []Package{
		{ImportPath: mod + "/internal/a", Deps: []string{"fmt", mod + "/internal/b"}},
		{ImportPath: mod + "/internal/b", Deps: []string{"github.com/x/y"}},
		{ImportPath: mod + "/internal/c", TestImports: []string{"golang.org/x/tools"}},
		{ImportPath: mod + "/internal/d", XTestImports: []string{"C"}},
		{ImportPath: "fmt", Standard: true, Deps: []string{"internal/fmtsort"}},
	}
	got := CheckStdlibOnly(mod, pkgs)
	if len(got) != 3 {
		t.Fatalf("got %v, want 3 violations", got)
	}
}

func TestCheckGoMod(t *testing.T) {
	if v := CheckGoMod("module m\n\ngo 1.27.0\n"); len(v) != 0 {
		t.Fatalf("unexpected %v", v)
	}
	for _, s := range []string{"require x.test/y v1.0.0", "require (\n\tx.test/y v1.0.0\n)", "  require x.test/y v1"} {
		if v := CheckGoMod("module m\n" + s + "\n"); len(v) != 1 {
			t.Fatalf("%q: got %v, want 1 violation", s, v)
		}
	}
}

func TestCheckWriterUsage(t *testing.T) {
	src := map[string]string{
		"plain":   "package p\nimport \"" + mod + "/internal/entra\"\nvar _ entra.Writer\n",
		"alias":   "package p\nimport e \"" + mod + "/internal/entra\"\nfunc f(w e.Writer) {}\n",
		"dot":     "package p\nimport . \"" + mod + "/internal/entra\"\n",
		"reader":  "package p\nimport \"" + mod + "/internal/entra\"\nvar _ entra.Reader\n",
		"shadow":  "package p\ntype entra struct{ Writer int }\nvar x entra\nvar _ = x.Writer\n",
		"allowed": "package p\nimport \"" + mod + "/internal/entra\"\nvar _ entra.Writer\n",
	}
	want := map[string]int{"plain": 1, "alias": 1, "dot": 1, "reader": 0, "shadow": 0, "allowed": 0}

	for name, body := range src {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			path := mod + "/internal/verify"
			if name == "allowed" {
				path = mod + "/internal/execute"
			}
			got, err := CheckWriterUsage(mod, []Package{{ImportPath: path, Dir: dir, GoFiles: []string{"x.go"}}}, WriterAllowed)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != want[name] {
				t.Fatalf("got %v, want %d", got, want[name])
			}
		})
	}
}

func writeGo(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWriterMethods(t *testing.T) {
	dir := writeGo(t, "package entra\ntype Reader interface{ Read() }\ntype Writer interface {\n\tSetA() error\n\tSetB() error\n}\n")
	got, err := WriterMethods(dir, []string{"x.go"})
	if err != nil || strings.Join(got, ",") != "SetA,SetB" {
		t.Fatalf("got %v %v", got, err)
	}
	for name, body := range map[string]string{
		"no writer":        "package entra\ntype Reader interface{ Read() }\n",
		"writer not iface": "package entra\ntype Writer struct{}\n",
		"empty writer":     "package entra\ntype Writer interface{}\n",
	} {
		if _, err := WriterMethods(writeGo(t, body), []string{"x.go"}); err == nil {
			t.Errorf("%s: expected error (check must not silently pass)", name)
		}
	}
}

func TestCheckWriteCalls(t *testing.T) {
	methods := []string{"SetConditionalAccessState"}
	cases := map[string]struct {
		pkg  string
		body string
		want int
	}{
		"inferred writer in cli": {"cmd/kodis",
			"package main\nfunc f(t T) { _, _ = t.Writer().SetConditionalAccessState(nil, \"a\", \"v\", \"enabled\") }\n", 1},
		"method value": {"internal/verify", "package verify\nvar f = w.SetConditionalAccessState\n", 1},
		"via local interface": {"internal/plan",
			"package plan\ntype w interface{ SetConditionalAccessState() }\nfunc f(x w) { x.SetConditionalAccessState() }\n", 1},
		"executor may write":     {"internal/execute", "package execute\nfunc f() { w.SetConditionalAccessState() }\n", 0},
		"passing writer is fine": {"cmd/kodis", "package main\nvar c = Config{Writer: t.Writer()}\n", 0},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			dir := writeGo(t, c.body)
			got, err := CheckWriteCalls(mod, []Package{{ImportPath: mod + "/" + c.pkg, Dir: dir, GoFiles: []string{"x.go"}}}, methods, WriterAllowed)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != c.want {
				t.Fatalf("got %v, want %d", got, c.want)
			}
		})
	}
}

// Review 4 finding 1: reflection and other call-by-name mechanisms are
// forbidden in every module package, not only under internal/ and cmd/.
// text/template, html/template and net/rpc call methods named in strings,
// which CheckWriteCalls cannot see.
func TestCallByNameForbiddenEverywhere(t *testing.T) {
	// Subpackages are covered too (fail closed, e.g. text/template/parse).
	for _, imp := range []string{"reflect", "unsafe", "text/template", "text/template/parse", "html/template", "net/rpc", "net/rpc/jsonrpc", "plugin"} {
		for _, pkg := range []string{"", "/bridge", "/_bridge", "/internal/verify", "/internal/execute", "/cmd/kodis"} {
			got := CheckBoundaries(mod, []Package{{ImportPath: mod + pkg, Imports: []string{imp}}}, Rules)
			if len(got) != 1 {
				t.Errorf("%q importing %s: got %v, want 1 violation", mod+pkg, imp, got)
			}
		}
	}
	for name, p := range map[string]Package{
		"stdlib package using reflect": {ImportPath: "encoding/json", Standard: true, Imports: []string{"reflect"}},
		"package outside the module":   {ImportPath: "example.test/other", Imports: []string{"reflect"}},
		"module prefix is not module":  {ImportPath: mod + "x/bridge", Imports: []string{"reflect"}},
		"only transitive via stdlib":   {ImportPath: mod + "/bridge", Imports: []string{"encoding/json"}, Deps: []string{"encoding/json", "reflect"}},
	} {
		if got := CheckBoundaries(mod, []Package{p}, Rules); len(got) != 0 {
			t.Errorf("%s: got %v, want none", name, got)
		}
	}
}

func TestCheckWriterUsageParseErrorFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte("not go"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := CheckWriterUsage(mod, []Package{{ImportPath: mod + "/internal/verify", Dir: dir, GoFiles: []string{"x.go"}}}, WriterAllowed)
	if err == nil {
		t.Fatal("expected parse error")
	}
}

// TestRepository applies all checks to the real module.
func TestRepository(t *testing.T) {
	root := goOutput(t, "list", "-m", "-f", "{{.Dir}}")
	module := goOutput(t, "list", "-m")

	// -deps also lists module packages imported from outside ./... (for
	// example from an "_" or testdata directory). -export provides the
	// export data CheckReflectTypes needs.
	pkgs := listExport(t, root)
	if len(pkgs) == 0 {
		t.Fatal("go list returned no packages")
	}

	gomod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var violations []string
	violations = append(violations, CheckGoMod(string(gomod))...)
	violations = append(violations, CheckStdlibOnly(module, pkgs)...)
	violations = append(violations, CheckBoundaries(module, pkgs, Rules)...)
	violations = append(violations, CheckImporters(module, pkgs, ImportRules)...)
	w, err := CheckWriterUsage(module, pkgs, WriterAllowed)
	if err != nil {
		t.Fatal(err)
	}
	violations = append(violations, w...)

	var entraPkg *Package
	for i := range pkgs {
		if pkgs[i].ImportPath == module+"/"+WriterPkg {
			entraPkg = &pkgs[i]
		}
	}
	if entraPkg == nil {
		t.Fatalf("%s not found", WriterPkg)
	}
	methods, err := WriterMethods(entraPkg.Dir, entraPkg.GoFiles)
	if err != nil {
		t.Fatal(err)
	}
	wc, err := CheckWriteCalls(module, pkgs, methods, WriterAllowed)
	if err != nil {
		t.Fatal(err)
	}
	violations = append(violations, wc...)
	// Review 5 finding 1.
	rt, err := CheckReflectTypes(module, pkgs)
	if err != nil {
		t.Fatal(err)
	}
	violations = append(violations, rt...)

	// Review 2 finding 3: repeat the checks over every non-test source
	// file, including ones the default build excludes, and allow build
	// constraints only on the approved files.
	src, err := SourcePackages(root, module)
	if err != nil {
		t.Fatal(err)
	}
	violations = append(violations, CheckStdlibOnly(module, src)...)
	violations = append(violations, CheckBoundaries(module, src, Rules)...)
	violations = append(violations, CheckImporters(module, src, ImportRules)...)
	if w, err := CheckWriterUsage(module, src, WriterAllowed); err != nil {
		t.Fatal(err)
	} else {
		violations = append(violations, w...)
	}
	if wc, err := CheckWriteCalls(module, src, methods, WriterAllowed); err != nil {
		t.Fatal(err)
	} else {
		violations = append(violations, wc...)
	}
	oses, arches := platforms(t)
	cf, err := CheckConstrainedFiles(root, src, ConstrainedAllowed, oses, arches)
	if err != nil {
		t.Fatal(err)
	}
	violations = append(violations, cf...)
	// Review 4 finding 2.
	violations = append(violations, CheckUnresolvedImports(module, src)...)
	ig, err := CheckIgnoredDirs(root, src)
	if err != nil {
		t.Fatal(err)
	}
	violations = append(violations, ig...)
	for _, v := range violations {
		t.Error(v)
	}
}

func goOutput(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// platforms returns the known GOOS and GOARCH values from the toolchain.
func platforms(t *testing.T) (map[string]bool, map[string]bool) {
	t.Helper()
	out := goOutput(t, "tool", "dist", "list")
	oses, arches := map[string]bool{}, map[string]bool{}
	for _, line := range strings.Fields(out) {
		os, arch, ok := strings.Cut(line, "/")
		if !ok {
			t.Fatalf("unexpected dist list line %q", line)
		}
		oses[os], arches[arch] = true, true
	}
	if !oses["linux"] || !oses["windows"] || !arches["amd64"] {
		t.Fatalf("dist list looks wrong: %v %v", oses, arches)
	}
	return oses, arches
}

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for rel, body := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSourcePackagesIncludesExcludedFiles(t *testing.T) {
	bypass := "package bridge\n\nimport \"" + mod + "/internal/mockentra\"\n\nfunc f(t *mockentra.Tenant) { t.Writer().SetConditionalAccessState() }\n"
	root := writeFiles(t, map[string]string{
		"cmd/kodis/main.go":            "package main\n",
		"cmd/kodis/zz_bypass.go":       "//go:build bypass\n\npackage main\n\nimport \"" + mod + "/internal/mockentra\"\n\nfunc f(t *mockentra.Tenant) { t.Writer().SetConditionalAccessState() }\n",
		"cmd/kodis/main_test.go":       "package main\nimport \"" + mod + "/internal/mockentra\"\n",
		"internal/verify/v_windows.go": "package verify\nimport \"" + mod + "/internal/mockentra\"\n",
		"internal/only/x.go":           "//go:build never\n\npackage only\nimport \"example.com/thirdparty\"\n",
		// Review 3 finding 2: ./... skips these, but they can be imported.
		"_bridge/b.go":                  bypass,
		"internal/testdata/bridge/b.go": bypass,
		"vendor/v/v.go":                 "package v\nimport \"example.com/thirdparty\"\n",
		// Review 4 finding 2: dot directories can be imported too.
		".hidden/x.go": "package hidden\nimport \"example.com/thirdparty\"\n",
		// A nested module is not part of this module.
		"nested/go.mod": "module example.test/nested\n",
		"nested/x.go":   "package nested\nimport \"example.com/thirdparty\"\n",
		"nested/y/y.go": "package y\nimport \"example.com/thirdparty\"\n",
	})
	src, err := SourcePackages(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, p := range src {
		paths = append(paths, p.ImportPath)
	}
	slices.Sort(paths)
	want := []string{mod + "/.hidden", mod + "/_bridge", mod + "/cmd/kodis", mod + "/internal/only", mod + "/internal/testdata/bridge", mod + "/internal/verify", mod + "/vendor/v"}
	if !slices.Equal(paths, want) {
		t.Fatalf("packages %v, want %v", paths, want)
	}
	for _, p := range src {
		if p.ImportPath == mod+"/cmd/kodis" && strings.Join(p.GoFiles, ",") != "main.go,zz_bypass.go" {
			t.Fatalf("cmd/kodis files %v (test files must be excluded, tagged files included)", p.GoFiles)
		}
	}
	calls, err := CheckWriteCalls(mod, src, []string{"SetConditionalAccessState"}, WriterAllowed)
	if err != nil || len(calls) != 3 {
		t.Fatalf("write calls (tagged file, _bridge, testdata): %v %v", calls, err)
	}
	if got := CheckImporters(mod, src, ImportRules); len(got) != 3 {
		t.Fatalf("mock imports from windows-only, _bridge and testdata packages: %v", got)
	}
	if got := CheckStdlibOnly(mod, src); len(got) != 3 {
		t.Fatalf("third-party imports from never-built, vendor and hidden packages: %v", got)
	}
	oses, arches := platforms(t)
	cf, err := CheckConstrainedFiles(root, src, nil, oses, arches)
	if err != nil || len(cf) != 3 {
		t.Fatalf("constrained files: %v %v", cf, err)
	}
}

// Review 3 finding 3: a dependency reached only through a build-
// constrained file is checked transitively, not just one import deep.
func TestSourcePackagesTransitiveThroughConstrainedFile(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"internal/approve/owner_unix.go":  "//go:build unix\n\npackage approve\n",
		"internal/approve/owner_other.go": "//go:build !unix\n\npackage approve\n\nimport \"" + mod + "/internal/bridge\"\n\nvar b = bridge.Build\n",
		"internal/bridge/bridge.go":       "package bridge\n\nimport \"" + mod + "/internal/plan\"\n\nvar Build = plan.Build\n",
		"internal/plan/plan.go":           "package plan\n\nimport \"" + mod + "/internal/model\"\n\nvar Build = model.X\n",
		"internal/model/model.go":         "package model\n\nvar X = 1\n",
	})
	src, err := SourcePackages(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range src {
		if p.ImportPath == mod+"/internal/approve" {
			if !slices.Contains(p.Deps, mod+"/internal/plan") || !slices.Contains(p.Deps, mod+"/internal/model") {
				t.Fatalf("approve deps %v lack the transitive plan/model", p.Deps)
			}
			if slices.Contains(p.Imports, mod+"/internal/plan") {
				t.Fatal("Imports must stay direct")
			}
		}
	}
	got := CheckBoundaries(mod, src, Rules)
	if len(got) != 1 || !strings.Contains(got[0], "internal/approve depends on "+mod+"/internal/plan") {
		t.Fatalf("approve -> bridge -> plan not reported: %v", got)
	}
}

// Review 4 finding 2: a dot directory reached only from a build-
// constrained file is neither in go list output nor skipped by the walk.
func TestSourcePackagesHiddenBridge(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"internal/approve/owner_unix.go":  "//go:build unix\n\npackage approve\n",
		"internal/approve/owner_other.go": "//go:build !unix\n\npackage approve\n\nimport \"" + mod + "/.hidden\"\n\nvar _ = hidden.F\n",
		".hidden/h.go":                    "package hidden\n\nimport \"" + mod + "/internal/mockentra\"\n\nfunc F(t *mockentra.Tenant) { t.Writer().SetConditionalAccessState() }\n",
		"internal/mockentra/m.go":         "package mockentra\n",
	})
	src, err := SourcePackages(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	got := CheckImporters(mod, src, ImportRules)
	if len(got) != 2 || !strings.Contains(got[0], mod+"/.hidden depends") || !strings.Contains(got[1], mod+"/internal/approve depends") {
		t.Fatalf("mock reached via hidden package: %v", got)
	}
	calls, err := CheckWriteCalls(mod, src, []string{"SetConditionalAccessState"}, WriterAllowed)
	if err != nil || len(calls) != 1 {
		t.Fatalf("write call in hidden package: %v %v", calls, err)
	}
}

func TestCheckUnresolvedImports(t *testing.T) {
	pkgs := []Package{
		{ImportPath: mod + "/internal/a", Imports: []string{"fmt", mod + "/internal/b", mod + "/internal/missing"}},
		{ImportPath: mod + "/internal/b", Imports: []string{mod + "/.gone"}},
	}
	got := CheckUnresolvedImports(mod, pkgs)
	if len(got) != 2 || !strings.Contains(got[0], "/internal/missing") || !strings.Contains(got[1], "/.gone") {
		t.Fatalf("got %v", got)
	}
	if got := CheckUnresolvedImports(mod, pkgs[:1]); len(got) != 2 {
		t.Fatalf("b missing from pkgs must be reported too: %v", got)
	}
}

func TestCheckIgnoredDirs(t *testing.T) {
	root := writeFiles(t, map[string]string{
		"x.go":                   "package kodis\n",
		"internal/a/a.go":        "package a\n",
		"internal/a_b/c.go":      "package c\n", // "_" not at the start
		".hidden/h.go":           "package h\n",
		"_bridge/b.go":           "package b\n",
		"internal/testdata/t.go": "package t\n",
		"vendor/v/v.go":          "package v\n",
		"internal/x/.y/z.go":     "package z\n",
	})
	src, err := SourcePackages(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CheckIgnoredDirs(root, src)
	if err != nil || len(got) != 5 {
		t.Fatalf("got %v %v, want 5", got, err)
	}
}

func TestClosureHandlesCycles(t *testing.T) {
	byPath := map[string]*Package{
		mod + "/a": {ImportPath: mod + "/a", Imports: []string{mod + "/b"}},
		mod + "/b": {ImportPath: mod + "/b", Imports: []string{mod + "/a", "fmt"}},
	}
	got := closure(mod, []string{mod + "/a"}, byPath)
	if strings.Join(got, ",") != mod+"/a,"+mod+"/b,fmt" {
		t.Fatalf("closure %v", got)
	}
}

func TestBuildConstraintDetection(t *testing.T) {
	oses, arches := platforms(t)
	for name, want := range map[string]bool{
		"x_windows.go":      true,
		"x_linux_amd64.go":  true,
		"x_arm64.go":        true,
		"owner_unix.go":     false, // "unix" is only a build tag, not a file suffix
		"linux.go":          false, // no "_": not constrained by name
		"windows_helper.go": false,
		"x_other.go":        false,
	} {
		if got := HasPlatformSuffix(name, oses, arches); got != want {
			t.Errorf("%s: got %v want %v", name, got, want)
		}
	}
	root := writeFiles(t, map[string]string{
		"a.go": "//go:build linux\n\npackage a\n",
		"b.go": "// +build linux\n\npackage a\n",
		"c.go": "// Package a is fine.\npackage a\n",
		"d.go": "package a\n\n//go:build linux\nvar x = 1\n", // after package clause: not a constraint
	})
	for name, want := range map[string]bool{"a.go": true, "b.go": true, "c.go": false, "d.go": false} {
		got, err := HasBuildTag(filepath.Join(root, name))
		if err != nil || got != want {
			t.Errorf("%s: got %v %v want %v", name, got, err, want)
		}
	}
	src, err := SourcePackages(root, mod)
	if err != nil {
		t.Fatal(err)
	}
	cf, err := CheckConstrainedFiles(root, src, []string{"a.go"}, oses, arches)
	if err != nil || len(cf) != 1 || !strings.Contains(cf[0], "b.go") {
		t.Fatalf("allowlist: %v %v", cf, err)
	}
}

// listExport runs `go list -export -deps -json ./...` in dir.
func listExport(t *testing.T, dir string) []Package {
	t.Helper()
	cmd := exec.Command("go", "list", "-export", "-deps", "-json", "./...")
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	raw, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, stderr.String())
	}
	var pkgs []Package
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		var p Package
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			t.Fatalf("decode go list output: %v", err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// Review 5 finding 1: a reflect.Value can be obtained from stdlib APIs
// without importing reflect, e.g. json.UnsupportedValueError.Value, and
// used to call methods by name. Any value of a reflect type (or
// unsafe.Pointer) in module code is reported, however it was obtained.
func TestCheckReflectTypes(t *testing.T) {
	const m = "example.test/rt"
	cases := map[string]struct {
		body string
		want bool
	}{
		"json error value": {`import ("encoding/json"; "errors")
func F(err error) { var uv *json.UnsupportedValueError; if errors.As(err, &uv) { _ = uv.Value.MethodByName("Set") } }`, true},
		"chained, never named": {`import "encoding/json"
func F(uv *json.UnsupportedValueError) { uv.Value.MethodByName("Set").Call(nil) }`, true},
		"testing/quick value": {`import ("math/rand"; "testing/quick")
func F(r *rand.Rand) { v, _ := quick.Value(nil, r); _ = v }`, true},
		"func value with reflect param": {`import "go/ast"
var F = ast.NotNilFilter`, true},
		"named func type with reflect param": {`import "go/ast"
var F ast.FieldFilter`, true},
		"json error message only": {`import ("encoding/json"; "errors")
func F(err error) string { var uv *json.UnsupportedValueError; if errors.As(err, &uv) { return uv.Str }; return "" }`, false},
		"plain json": {`import "encoding/json"
func F(v any) ([]byte, error) { return json.Marshal(v) }`, false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeFiles(t, map[string]string{
				"go.mod":      "module " + m + "\n\ngo 1.27.0\n",
				"p/p.go":      "package p\n\n" + c.body + "\n",
				"p/p_test.go": "package p\n\nimport \"reflect\"\n\nvar _ reflect.Value\n",
			})
			got, err := CheckReflectTypes(m, listExport(t, root))
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) > 0) != c.want {
				t.Fatalf("got %v, want violation %v", got, c.want)
			}
		})
	}
}
