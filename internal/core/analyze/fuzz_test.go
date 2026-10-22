package analyze_test

import (
	"os"
	"path/filepath"
	"testing"

	"fplogin/internal/core/analyze"
)

// FuzzPAMParser tests that arbitrary PAM configurations never trigger panics or infinite recursion.
func FuzzPAMParser(f *testing.F) {
	f.Add("auth required pam_unix.so\n")
	f.Add("@include system-auth\nauth optional pam_kwallet5.so\n")
	f.Add("@include recursive\n")
	f.Add("# broken lines\nauth [bad_val=1] pam_something.so arg1 arg2\n")
	f.Add("substack login\ninclude login\n")

	f.Fuzz(func(t *testing.T, pamContent string) {
		tmpDir := t.TempDir()
		pamDir := filepath.Join(tmpDir, "etc", "pam.d")
		if err := os.MkdirAll(pamDir, 0o755); err != nil {
			return
		}

		serviceFile := filepath.Join(pamDir, "fuzz-service")
		if err := os.WriteFile(serviceFile, []byte(pamContent), 0o644); err != nil {
			return
		}

		// Also create a circular include target to test cycle protection under fuzzing
		circularFile := filepath.Join(pamDir, "recursive")
		_ = os.WriteFile(circularFile, []byte("@include fuzz-service\n"), 0o644)

		// Must not panic or hang
		_, _ = analyze.ParsePAM(tmpDir, "fuzz-service", 10)
	})
}
