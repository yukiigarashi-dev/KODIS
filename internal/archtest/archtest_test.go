package archtest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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

func TestReflectAndUnsafeForbidden(t *testing.T) {
	for _, imp := range []string{"reflect", "unsafe"} {
		for _, pkg := range []string{"internal/verify", "cmd/kodis"} {
			got := CheckBoundaries(mod, []Package{{ImportPath: mod + "/" + pkg, Imports: []string{imp}}}, Rules)
			if len(got) != 1 {
				t.Errorf("%s importing %s: got %v", pkg, imp, got)
			}
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

	cmd := exec.Command("go", "list", "-json", "./...")
	cmd.Dir = root
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
