// Package processrunner executes one-request/one-response protocol processes
// with bounded resources and process-group cancellation.
package processrunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"fplogin/internal/descriptortrust"
)

var (
	ErrTimeout        = errors.New("protocol process timed out")
	ErrInputTooLarge  = errors.New("protocol process input exceeded limit")
	ErrOutputTooLarge = errors.New("protocol process output exceeded limit")
	ErrProcessFailed  = errors.New("protocol process failed")
)

type Config struct {
	Timeout        time.Duration
	MaxInputBytes  int
	MaxStdoutBytes int
	MaxStderrBytes int
	Environment    []string
	Arguments      []string
}

type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

type Runner struct{ config Config }

func New(config Config) (Runner, error) {
	if config.Timeout <= 0 || config.MaxInputBytes <= 0 || config.MaxStdoutBytes <= 0 || config.MaxStderrBytes <= 0 {
		return Runner{}, errors.New("runner timeout and byte limits must be positive")
	}
	return Runner{config: config}, nil
}

func (r Runner) Run(ctx context.Context, executable string, input []byte) (Result, error) {
	return r.run(ctx, executable, input, r.config.Arguments, r.config.Environment, "")
}

// RunUnprivileged launches a validated adapter with credentials supplied by trusted core wiring.
func (r Runner) RunUnprivileged(ctx context.Context, executable string, input []byte, uid, gid uint32) (Result, error) {
	if uid == 0 || gid == 0 || uid == ^uint32(0) || gid == ^uint32(0) {
		return Result{}, errors.New("adapter requires a non-root uid and gid")
	}
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return Result{}, errors.New("adapter executable must be canonical and absolute")
	}
	const helper = "/usr/bin/setpriv"
	if err := descriptortrust.ValidatePackagedExecutable(helper); err != nil {
		return Result{}, fmt.Errorf("validate adapter credential helper: %w", err)
	}
	args := []string{"--no-new-privs", "--clear-groups", "--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all",
		"--reuid", strconv.FormatUint(uint64(uid), 10), "--regid", strconv.FormatUint(uint64(gid), 10), "--", executable}
	return r.run(ctx, helper, input, args, nil, "/")
}

func (r Runner) run(ctx context.Context, executable string, input []byte, args, env []string, dir string) (Result, error) {
	if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
		return Result{}, errors.New("protocol executable path must be canonical and absolute")
	}
	if len(input) > r.config.MaxInputBytes {
		return Result{}, ErrInputTooLarge
	}
	deadlineContext, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()

	stdout := newLimitedBuffer(r.config.MaxStdoutBytes)
	stderr := newLimitedBuffer(r.config.MaxStderrBytes)
	command := exec.CommandContext(deadlineContext, executable, args...)
	command.Dir = dir
	command.Env = append(append([]string(nil), env...), "LANG=C", "LC_ALL=C")
	command.Stdin = bytes.NewReader(input)
	command.Stdout = stdout
	command.Stderr = stderr
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	command.WaitDelay = 250 * time.Millisecond
	command.Cancel = func() error {
		if command.Process == nil {
			return nil
		}
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}

	err := command.Run()
	result := Result{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), ExitCode: exitCode(err)}
	if stdout.overflow || stderr.overflow {
		return result, ErrOutputTooLarge
	}
	if deadlineContext.Err() != nil {
		return result, fmt.Errorf("%w: %v", ErrTimeout, deadlineContext.Err())
	}
	if err != nil {
		return result, fmt.Errorf("%w (exit %d): %v", ErrProcessFailed, result.ExitCode, err)
	}
	return result, nil
}

type limitedBuffer struct {
	limit    int
	buffer   bytes.Buffer
	overflow bool
}

func newLimitedBuffer(limit int) *limitedBuffer { return &limitedBuffer{limit: limit} }
func (b *limitedBuffer) Write(data []byte) (int, error) {
	remaining := b.limit - b.buffer.Len()
	if remaining <= 0 {
		b.overflow = true
		return len(data), nil
	}
	if len(data) > remaining {
		_, _ = b.buffer.Write(data[:remaining])
		b.overflow = true
		return len(data), nil
	}
	return b.buffer.Write(data)
}
func (b *limitedBuffer) Bytes() []byte { return b.buffer.Bytes() }

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
