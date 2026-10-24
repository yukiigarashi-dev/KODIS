//go:build unix

package archtest

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func wrapper(t *testing.T) string {
	t.Helper()
	return filepath.Join(goOutput(t, "list", "-m", "-f", "{{.Dir}}"), "scripts", "safe-test.sh")
}

// Review 2 finding 4: the limits may only be lowered. Invalid values are
// rejected before anything runs, so this needs no systemd.
func TestSafeTestRejectsRaisedOrInvalidLimits(t *testing.T) {
	w := wrapper(t)
	for _, v := range []string{
		"KODIS_MEM_MAX=infinity", "KODIS_MEM_MAX=", "KODIS_MEM_MAX=0", "KODIS_MEM_MAX=3G",
		"KODIS_MEM_MAX=2049M", "KODIS_MEM_MAX=-1G", "KODIS_MEM_MAX=01G", "KODIS_MEM_MAX=1T",
		"KODIS_MEM_MAX=99999999999999999999",
		"KODIS_CPU_QUOTA=201%", "KODIS_CPU_QUOTA=200", "KODIS_CPU_QUOTA=", "KODIS_CPU_QUOTA=infinity",
		"KODIS_TASKS_MAX=infinity", "KODIS_TASKS_MAX=513", "KODIS_TASKS_MAX=0",
		"KODIS_TIMEOUT=0", "KODIS_TIMEOUT=301", "KODIS_TIMEOUT=", "KODIS_TIMEOUT=1.5",
	} {
		t.Run(v, func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "ran")
			cmd := exec.Command("sh", w, "touch", marker)
			cmd.Env = append(filterEnv(os.Environ()), v)
			err := cmd.Run()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 2 {
				t.Fatalf("got %v, want exit status 2", err)
			}
			if _, err := os.Stat(marker); err == nil {
				t.Fatal("command ran despite invalid limits")
			}
		})
	}
}

func userScopeAvailable() bool {
	return exec.Command("systemd-run", "--user", "--scope", "--quiet", "--collect", "true").Run() == nil
}

const readLimits = `cg=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup); for f in memory.max memory.swap.max cpu.max pids.max; do printf "%s=%s\n" $f "$(cat $cg/$f)"; done`

// TestSafeTestAppliesLimits checks the limits inside the scope, so
// removing a -p line from the wrapper fails this test. Skipped where no
// systemd user bus is reachable (e.g. read-only review sandboxes).
func TestSafeTestAppliesLimits(t *testing.T) {
	if !userScopeAvailable() {
		t.Skip("no systemd user scope available")
	}
	w := wrapper(t)
	for name, c := range map[string]struct {
		env  []string
		want []string
	}{
		"defaults": {nil, []string{"memory.max=2147483648", "memory.swap.max=0", "cpu.max=200000 100000", "pids.max=512"}},
		"lowered": {[]string{"KODIS_MEM_MAX=256M", "KODIS_CPU_QUOTA=50%", "KODIS_TASKS_MAX=64", "KODIS_TIMEOUT=30"},
			[]string{"memory.max=268435456", "memory.swap.max=0", "cpu.max=50000 100000", "pids.max=64"}},
	} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("sh", w, "sh", "-c", readLimits)
			cmd.Env = append(filterEnv(os.Environ()), c.env...)
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%v", err)
			}
			got := strings.Split(strings.TrimSpace(string(out)), "\n")
			if strings.Join(got, ";") != strings.Join(c.want, ";") {
				t.Fatalf("limits %q, want %q", got, c.want)
			}
		})
	}
	t.Run("timeout", func(t *testing.T) {
		cmd := exec.Command("sh", w, "sleep", "30")
		cmd.Env = append(filterEnv(os.Environ()), "KODIS_TIMEOUT=1")
		err := cmd.Run()
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 124 {
			t.Fatalf("got %v, want timeout exit 124", err)
		}
	})
}

// filterEnv drops inherited KODIS_* limits so each case sets its own.
func filterEnv(env []string) []string {
	var out []string
	for _, kv := range env {
		if !strings.HasPrefix(kv, "KODIS_") {
			out = append(out, kv)
		}
	}
	return out
}
