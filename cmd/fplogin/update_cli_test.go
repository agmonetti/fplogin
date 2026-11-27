package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestUpdate_CheckApplyAndUpToDate(t *testing.T) {
	fploginBytes := []byte("fake-fplogin-pkg-v1.1.0")
	sddmBytes := []byte("fake-sddm-pkg-0.21.0-7")
	fploginSHA := sha256Hex(fploginBytes)
	sddmSHA := sha256Hex(sddmBytes)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/agmonetti/fplogin/releases/latest":
			_ = json.NewEncoder(w).Encode(githubRelease{
				TagName: "v1.1.0",
				Assets: []githubReleaseAsset{
					{Name: "SHA256SUMS", BrowserDownloadURL: srv.URL + "/assets/SHA256SUMS"},
					{Name: "fplogin-git-1.1.0-1-x86_64.pkg.tar.zst", BrowserDownloadURL: srv.URL + "/assets/fplogin.pkg.tar.zst"},
					{Name: "sddm-fplogin-0.21.0-7-x86_64.pkg.tar.zst", BrowserDownloadURL: srv.URL + "/assets/sddm.pkg.tar.zst"},
				},
			})
		case "/assets/SHA256SUMS":
			fmt.Fprintf(w, "%s  fplogin-git-1.1.0-1-x86_64.pkg.tar.zst\n%s  sddm-fplogin-0.21.0-7-x86_64.pkg.tar.zst\n", fploginSHA, sddmSHA)
		case "/assets/fplogin.pkg.tar.zst":
			_, _ = w.Write(fploginBytes)
		case "/assets/sddm.pkg.tar.zst":
			_, _ = w.Write(sddmBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	statePath := filepath.Join(t.TempDir(), "release-state.json")
	var installedPaths []string
	makeDeps := func(euid int, in string, out, errBuf *bytes.Buffer) updateDeps {
		return updateDeps{
			httpClient: srv.Client(),
			getEuid:    func() int { return euid },
			queryPacman: func(pkg string) (string, bool) {
				if pkg == "fplogin-git" {
					return "fplogin-git 1.0.0-1", true
				}
				if pkg == "sddm-fplogin" {
					return "sddm-fplogin 0.21.0-6", true
				}
				return "", false
			},
			installPkgs: func(paths []string) error {
				installedPaths = append([]string(nil), paths...)
				return nil
			},
			stdin:  strings.NewReader(in),
			stdout: out,
			stderr: errBuf,
		}
	}

	// 1. Unprivileged --check reports update available and does not install.
	var out, errBuf bytes.Buffer
	err := executeUpdate([]string{"--check", "--api-base", srv.URL, "--state", statePath}, makeDeps(1000, "", &out, &errBuf))
	if err != nil {
		t.Fatalf("--check failed: %v", err)
	}
	if !strings.Contains(out.String(), "update available") || len(installedPaths) != 0 {
		t.Fatalf("unexpected --check output=%q installed=%v", out.String(), installedPaths)
	}

	// 2. Root apply verifies both packages, confirms, installs, and records SHAs.
	out.Reset()
	err = executeUpdate([]string{"--api-base", srv.URL, "--state", statePath}, makeDeps(0, "y\n", &out, &errBuf))
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if len(installedPaths) != 2 {
		t.Fatalf("expected 2 installed packages, got %v", installedPaths)
	}
	if !strings.Contains(out.String(), "Updated successfully to v1.1.0") {
		t.Fatalf("unexpected apply output: %q", out.String())
	}

	// 3. Re-running reports Already up to date and installs nothing.
	installedPaths = nil
	out.Reset()
	err = executeUpdate([]string{"--api-base", srv.URL, "--state", statePath}, makeDeps(0, "", &out, &errBuf))
	if err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if !strings.Contains(out.String(), "Already up to date (v1.1.0)") || len(installedPaths) != 0 {
		t.Fatalf("expected up-to-date, got output=%q installed=%v", out.String(), installedPaths)
	}
}

func TestUpdate_RejectsSHA256MismatchBeforeInstall(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/agmonetti/fplogin/releases/latest":
			_ = json.NewEncoder(w).Encode(githubRelease{
				TagName: "v1.1.0",
				Assets: []githubReleaseAsset{
					{Name: "SHA256SUMS", BrowserDownloadURL: srv.URL + "/assets/SHA256SUMS"},
					{Name: "fplogin-git-1.1.0-1-x86_64.pkg.tar.zst", BrowserDownloadURL: srv.URL + "/assets/fplogin.pkg.tar.zst"},
				},
			})
		case "/assets/SHA256SUMS":
			fmt.Fprintf(w, "%s  fplogin-git-1.1.0-1-x86_64.pkg.tar.zst\n", sha256Hex([]byte("expected-content")))
		case "/assets/fplogin.pkg.tar.zst":
			_, _ = w.Write([]byte("tampered-content"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	calledInstall := false
	statePath := filepath.Join(t.TempDir(), "release-state.json")
	var out, errBuf bytes.Buffer
	err := executeUpdate([]string{"--yes", "--api-base", srv.URL, "--state", statePath}, updateDeps{
		httpClient:  srv.Client(),
		getEuid:     func() int { return 0 },
		queryPacman: func(string) (string, bool) { return "", false },
		installPkgs: func([]string) error { calledInstall = true; return nil },
		stdin:       strings.NewReader(""),
		stdout:      &out,
		stderr:      &errBuf,
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected SHA-256 mismatch error, got %v", err)
	}
	if calledInstall {
		t.Fatal("pacman -U must never run on SHA-256 mismatch")
	}
	if _, statErr := os.Stat(statePath); !os.IsNotExist(statErr) {
		t.Fatalf("state file must not be written on failure: %v", statErr)
	}
}

func TestParseSHA256Sums_RejectsUnsafeEntries(t *testing.T) {
	validSum := sha256Hex([]byte("ok"))
	if _, err := parseSHA256Sums(validSum + "  ../evil.pkg.tar.zst\n"); err == nil {
		t.Fatal("expected traversal filename rejection")
	}
	if _, err := parseSHA256Sums("not-a-sha  fplogin-git-1.0.0.pkg.tar.zst\n"); err == nil {
		t.Fatal("expected invalid digest rejection")
	}
}

func TestUpdate_GenericLinuxTarballFlow(t *testing.T) {
	tarBytes := []byte("fake-linux-tarball-v1.0.1")
	tarSHA := sha256Hex(tarBytes)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/agmonetti/fplogin/releases/latest":
			_ = json.NewEncoder(w).Encode(githubRelease{
				TagName: "v1.0.1",
				Assets: []githubReleaseAsset{
					{Name: "SHA256SUMS", BrowserDownloadURL: srv.URL + "/assets/SHA256SUMS"},
					{Name: "fplogin-linux-x86_64.tar.gz", BrowserDownloadURL: srv.URL + "/assets/fplogin-linux-x86_64.tar.gz"},
				},
			})
		case "/assets/SHA256SUMS":
			fmt.Fprintf(w, "%s  fplogin-linux-x86_64.tar.gz\n", tarSHA)
		case "/assets/fplogin-linux-x86_64.tar.gz":
			_, _ = w.Write(tarBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	statePath := filepath.Join(t.TempDir(), "release-state.json")
	var installedTar string
	var out, errBuf bytes.Buffer
	err := executeUpdate([]string{"--yes", "--api-base", srv.URL, "--state", statePath}, updateDeps{
		httpClient:     srv.Client(),
		getEuid:        func() int { return 0 },
		hasPacman:      func() bool { return false },
		queryPacman:    func(string) (string, bool) { return "", false },
		installTarball: func(p string) error { installedTar = p; return nil },
		stdin:          strings.NewReader(""),
		stdout:         &out,
		stderr:         &errBuf,
	})
	if err != nil {
		t.Fatalf("generic linux update failed: %v", err)
	}
	if installedTar == "" || !strings.Contains(out.String(), "Updated successfully to v1.0.1") {
		t.Fatalf("expected tarball install, got tar=%q out=%q", installedTar, out.String())
	}
}

func TestSelectUpdateCandidatesForArch_FiltersMismatchedArch(t *testing.T) {
	assets := []githubReleaseAsset{
		{Name: "fplogin-git-1.0.1-1-x86_64.pkg.tar.zst", BrowserDownloadURL: "https://example.invalid/x86_64"},
		{Name: "sddm-fplogin-0.21.0-6-x86_64.pkg.tar.zst", BrowserDownloadURL: "https://example.invalid/sddm-x86_64"},
	}
	sums := map[string]string{
		"fplogin-git-1.0.1-1-x86_64.pkg.tar.zst":   sha256Hex([]byte("a")),
		"sddm-fplogin-0.21.0-6-x86_64.pkg.tar.zst": sha256Hex([]byte("b")),
	}
	query := func(pkg string) (string, bool) { return pkg + " 1.0.0-1", true }

	if got := selectUpdateCandidatesForArch(assets, sums, releaseState{Packages: map[string]string{}}, query, "aarch64"); len(got) != 0 {
		t.Fatalf("expected no Arch candidates on aarch64 for x86_64-only release, got %+v", got)
	}
	if got := selectUpdateCandidatesForArch(assets, sums, releaseState{Packages: map[string]string{}}, query, "x86_64"); len(got) != 2 {
		t.Fatalf("expected 2 Arch candidates on x86_64, got %+v", got)
	}
}

func TestUpdate_WebRedirectFlowWithoutAPI(t *testing.T) {
	fploginBytes := []byte("web-release-fplogin-v1.0.2")
	fploginSHA := sha256Hex(fploginBytes)

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/agmonetti/fplogin/releases/latest":
			http.Redirect(w, r, "/agmonetti/fplogin/releases/tag/v1.0.2", http.StatusFound)
		case "/agmonetti/fplogin/releases/download/v1.0.2/SHA256SUMS":
			fmt.Fprintf(w, "%s  fplogin-git-1.0.2-1-x86_64.pkg.tar.zst\n", fploginSHA)
		case "/agmonetti/fplogin/releases/download/v1.0.2/fplogin-git-1.0.2-1-x86_64.pkg.tar.zst":
			_, _ = w.Write(fploginBytes)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	statePath := filepath.Join(t.TempDir(), "release-state.json")
	var installed []string
	var out, errBuf bytes.Buffer
	err := executeUpdate([]string{"--yes", "--web-base", srv.URL, "--state", statePath}, updateDeps{
		httpClient:  srv.Client(),
		getEuid:     func() int { return 0 },
		hasPacman:   func() bool { return true },
		queryPacman: func(string) (string, bool) { return "fplogin-git 1.0.1-1", true },
		installPkgs: func(paths []string) error { installed = append([]string(nil), paths...); return nil },
		stdin:       strings.NewReader(""),
		stdout:      &out,
		stderr:      &errBuf,
	})
	if err != nil {
		t.Fatalf("web redirect update failed: %v", err)
	}
	if len(installed) != 1 || !strings.Contains(out.String(), "Updated successfully to v1.0.2") {
		t.Fatalf("unexpected web update result installed=%v out=%q", installed, out.String())
	}
}
