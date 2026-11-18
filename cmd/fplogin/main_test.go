package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDisabledCommands(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "fplogin")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build fplogin: %v\n%s", err, out)
	}

	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"install"}, 1, "Error: install: host installation is disabled"},
		{[]string{"install", "--yes", "--adapter-dir", "/nonexistent"}, 1, "Error: install: host installation is disabled"},
		{[]string{"uninstall"}, 1, "Error: uninstall: host uninstallation is disabled"},
		{[]string{"uninstall", "--force", "--manifest", "/nonexistent"}, 1, "Error: uninstall: host uninstallation is disabled"},
		{[]string{"install", "--dry-run", "--yes"}, 2, "flag provided but not defined"},
		{[]string{"install", "--dry-run", "--adapter-dir=/nonexistent"}, 2, "flag provided but not defined"},
		{[]string{"help"}, 0, "unprivileged --dry-run (read-only)"},
		{[]string{"install", "--help"}, 0, "Dry-run only reports proposed changes"},
		{[]string{"uninstall", "--help"}, 0, "host uninstallation is disabled"},
		{[]string{"status", "--help"}, 0, "Path to install manifest"},
		{[]string{"analyze", "--help"}, 0, "Output report as JSON"},
	} {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, bin, tc.args...)
			cmd.Dir = t.TempDir()
			out, err := cmd.CombinedOutput()
			if err != nil && cmd.ProcessState == nil {
				t.Fatal(err)
			}
			code := cmd.ProcessState.ExitCode()
			if code != tc.code || !strings.Contains(string(out), tc.want) {
				t.Fatalf("exit %d, output %q; want exit %d and %q", code, out, tc.code, tc.want)
			}
			if entries, err := os.ReadDir(cmd.Dir); err != nil || len(entries) != 0 {
				t.Fatalf("unexpected files in working directory: %v (%v)", entries, err)
			}
		})
	}
}
