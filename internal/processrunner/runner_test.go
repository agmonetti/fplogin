package processrunner_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"fplogin/internal/processrunner"
)

func TestNew_Validation(t *testing.T) {
	valid := processrunner.Config{
		Timeout:        time.Second,
		MaxInputBytes:  1024,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
	}

	if _, err := processrunner.New(valid); err != nil {
		t.Fatalf("expected valid config to succeed, got %v", err)
	}

	invalidCases := []processrunner.Config{
		{Timeout: 0, MaxInputBytes: 1024, MaxStdoutBytes: 1024, MaxStderrBytes: 1024},
		{Timeout: time.Second, MaxInputBytes: 0, MaxStdoutBytes: 1024, MaxStderrBytes: 1024},
		{Timeout: time.Second, MaxInputBytes: 1024, MaxStdoutBytes: 0, MaxStderrBytes: 1024},
		{Timeout: time.Second, MaxInputBytes: 1024, MaxStdoutBytes: 1024, MaxStderrBytes: 0},
	}

	for i, c := range invalidCases {
		if _, err := processrunner.New(c); err == nil {
			t.Fatalf("case %d: expected error for invalid config, got nil", i)
		}
	}
}

func TestRunner_PathValidation(t *testing.T) {
	r, err := processrunner.New(processrunner.Config{
		Timeout:        time.Second,
		MaxInputBytes:  1024,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Relative path
	if _, err := r.Run(context.Background(), "bin/relative", nil); err == nil {
		t.Fatal("expected error for relative executable path")
	}

	// Non-canonical absolute path
	if _, err := r.Run(context.Background(), "/bin/../bin/sh", nil); err == nil {
		t.Fatal("expected error for non-canonical executable path")
	}
}

func TestRunner_InputLimit(t *testing.T) {
	r, err := processrunner.New(processrunner.Config{
		Timeout:        time.Second,
		MaxInputBytes:  4,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}

	_, err = r.Run(context.Background(), sh, []byte("12345"))
	if !errors.Is(err, processrunner.ErrInputTooLarge) {
		t.Fatalf("expected ErrInputTooLarge, got: %v", err)
	}
}

func TestRunner_Success(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}

	r, err := processrunner.New(processrunner.Config{
		Timeout:        2 * time.Second,
		MaxInputBytes:  1024,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
		Arguments:      []string{"-c", "cat"},
	})
	if err != nil {
		t.Fatal(err)
	}

	input := []byte("hello processrunner")
	res, err := r.Run(context.Background(), sh, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res.Stdout) != string(input) {
		t.Fatalf("expected stdout %q, got %q", string(input), string(res.Stdout))
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d", res.ExitCode)
	}
}

func TestRunner_OutputLimit(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}

	r, err := processrunner.New(processrunner.Config{
		Timeout:        2 * time.Second,
		MaxInputBytes:  1024,
		MaxStdoutBytes: 8,
		MaxStderrBytes: 1024,
		Arguments:      []string{"-c", "echo 'this is way too long for stdout'"},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = r.Run(context.Background(), sh, nil)
	if !errors.Is(err, processrunner.ErrOutputTooLarge) {
		t.Fatalf("expected ErrOutputTooLarge, got: %v", err)
	}
}

func TestRunner_Timeout(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}

	r, err := processrunner.New(processrunner.Config{
		Timeout:        100 * time.Millisecond,
		MaxInputBytes:  1024,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
		Arguments:      []string{"-c", "sleep 2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	_, err = r.Run(context.Background(), sh, nil)
	duration := time.Since(start)

	if !errors.Is(err, processrunner.ErrTimeout) {
		t.Fatalf("expected ErrTimeout, got: %v", err)
	}
	if duration >= time.Second {
		t.Fatalf("execution took too long (%v), timeout did not kill promptly", duration)
	}
}

func TestRunner_NonZeroExit(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}

	r, err := processrunner.New(processrunner.Config{
		Timeout:        2 * time.Second,
		MaxInputBytes:  1024,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
		Arguments:      []string{"-c", "exit 42"},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background(), sh, nil)
	if !errors.Is(err, processrunner.ErrProcessFailed) {
		t.Fatalf("expected ErrProcessFailed, got: %v", err)
	}
	if res.ExitCode != 42 {
		t.Fatalf("expected exit code 42, got %d", res.ExitCode)
	}
}

func TestRunner_StderrCapture(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh not found")
	}

	r, err := processrunner.New(processrunner.Config{
		Timeout:        2 * time.Second,
		MaxInputBytes:  1024,
		MaxStdoutBytes: 1024,
		MaxStderrBytes: 1024,
		Arguments:      []string{"-c", "echo 'stderr error message' >&2; exit 1"},
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := r.Run(context.Background(), sh, nil)
	if !errors.Is(err, processrunner.ErrProcessFailed) {
		t.Fatalf("expected ErrProcessFailed, got: %v", err)
	}
	if len(res.Stderr) == 0 {
		t.Fatal("expected stderr to be captured")
	}
}

func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
