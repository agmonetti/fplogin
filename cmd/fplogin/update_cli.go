package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	defaultUpdateRepo      = "agmonetti/fplogin"
	defaultGitHubAPIBase   = "https://api.github.com"
	defaultUpdateStatePath = "/var/lib/fplogin/release-state.json"
	maxSHA256SumsBytes     = 64 * 1024
	maxReleasePkgBytes     = 256 * 1024 * 1024
)

var (
	repoPattern   = regexp.MustCompile(`^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$`)
	sha256Pattern = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

type githubRelease struct {
	TagName string               `json:"tag_name"`
	HTMLURL string               `json:"html_url"`
	Assets  []githubReleaseAsset `json:"assets"`
}

type githubReleaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

type releaseState struct {
	Tag       string            `json:"tag"`
	UpdatedAt string            `json:"updated_at"`
	Packages  map[string]string `json:"packages"`
}

type updateCandidate struct {
	PkgName     string
	AssetName   string
	DownloadURL string
	RemoteSHA   string
	LocalSHA    string
	Installed   string
	Changed     bool
}

type updateDeps struct {
	httpClient   *http.Client
	getEuid      func() int
	queryPacman  func(pkg string) (string, bool)
	installPkgs  func(paths []string) error
	stdin        io.Reader
	stdout       io.Writer
	stderr       io.Writer
}

func defaultUpdateDeps() updateDeps {
	return updateDeps{
		httpClient: &http.Client{Timeout: 30 * time.Second},
		getEuid:    os.Geteuid,
		queryPacman: func(pkg string) (string, bool) {
			out, err := exec.Command("pacman", "-Q", pkg).Output()
			if err != nil {
				return "", false
			}
			return strings.TrimSpace(string(out)), true
		},
		installPkgs: func(paths []string) error {
			args := append([]string{"-U", "--noconfirm"}, paths...)
			cmd := exec.Command("pacman", args...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		},
		stdin:  os.Stdin,
		stdout: os.Stdout,
		stderr: os.Stderr,
	}
}

func runUpdate(args []string) {
	if err := executeUpdate(args, defaultUpdateDeps()); err != nil {
		fmt.Fprintf(os.Stderr, "Error: update: %v\n", err)
		os.Exit(1)
	}
}

func executeUpdate(args []string, deps updateDeps) error {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(deps.stderr)
	checkOnly := fs.Bool("check", false, "Check for a newer release and compare SHA-256 without installing (unprivileged)")
	yes := fs.Bool("yes", false, "Skip interactive confirmation before running pacman -U")
	repo := fs.String("repo", defaultUpdateRepo, "GitHub owner/repo to query for releases")
	tag := fs.String("tag", "", "Specific release tag to fetch (default: latest)")
	apiBase := fs.String("api-base", defaultGitHubAPIBase, "GitHub API base URL")
	statePath := fs.String("state", defaultUpdateStatePath, "Path to local release SHA-256 state file")
	fs.Usage = func() {
		fmt.Fprintf(deps.stderr, `Usage:
  fplogin update --check [--repo OWNER/REPO] [--tag TAG] [--state PATH]
  sudo fplogin update [--yes] [--repo OWNER/REPO] [--tag TAG] [--state PATH]

Compares SHA-256 checksums from the latest GitHub Release against the locally
recorded release state and updates changed Arch packages after verification.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}

	if !*checkOnly && deps.getEuid() != 0 {
		return errors.New("requires root privileges (use --check for unprivileged check)")
	}
	if !repoPattern.MatchString(*repo) {
		return fmt.Errorf("invalid --repo %q (expected owner/repo)", *repo)
	}
	if err := validateURL(*apiBase); err != nil {
		return fmt.Errorf("invalid --api-base: %w", err)
	}

	rel, err := fetchGitHubRelease(deps.httpClient, strings.TrimRight(*apiBase, "/"), *repo, *tag)
	if err != nil {
		return err
	}

	sumsAsset, ok := findAssetByName(rel.Assets, "SHA256SUMS")
	if !ok {
		return fmt.Errorf("release %s does not include a SHA256SUMS asset", rel.TagName)
	}
	sums, err := fetchSHA256Sums(deps.httpClient, sumsAsset.BrowserDownloadURL)
	if err != nil {
		return fmt.Errorf("fetch SHA256SUMS: %w", err)
	}

	state, err := loadReleaseState(*statePath)
	if err != nil {
		if *checkOnly && errors.Is(err, os.ErrPermission) {
			fmt.Fprintf(deps.stderr, "Note: %s requires root to read; showing remote SHAs without local SHA baseline.\n", *statePath)
			state = releaseState{Packages: map[string]string{}}
		} else {
			return fmt.Errorf("load state %s: %w", *statePath, err)
		}
	}

	candidates := selectUpdateCandidates(rel.Assets, sums, state, deps.queryPacman)
	if len(candidates) == 0 {
		return fmt.Errorf("release %s contains no matching Arch packages in SHA256SUMS", rel.TagName)
	}

	var toUpdate []updateCandidate
	fmt.Fprintf(deps.stdout, "Release: %s\n", rel.TagName)
	for _, c := range candidates {
		localDesc := "untracked"
		if c.LocalSHA != "" {
			localDesc = shortSHA(c.LocalSHA)
		} else if c.Installed != "" {
			localDesc = c.Installed + " (no recorded SHA)"
		}
		status := "up-to-date"
		if c.Changed {
			status = "update available"
			toUpdate = append(toUpdate, c)
		}
		fmt.Fprintf(deps.stdout, "  %-14s %-16s local=%s remote=%s (%s)\n",
			c.PkgName, status, localDesc, shortSHA(c.RemoteSHA), c.AssetName)
	}

	if len(toUpdate) == 0 {
		fmt.Fprintf(deps.stdout, "Already up to date (%s).\n", rel.TagName)
		return nil
	}
	if *checkOnly {
		fmt.Fprintf(deps.stdout, "Run 'sudo fplogin update' to download, verify, and install %d package(s).\n", len(toUpdate))
		return nil
	}

	tmpDir, err := os.MkdirTemp("", "fplogin-update-*")
	if err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	if err := os.Chmod(tmpDir, 0o700); err != nil {
		return fmt.Errorf("chmod staging dir: %w", err)
	}

	var downloaded []string
	for _, c := range toUpdate {
		dest := filepath.Join(tmpDir, c.AssetName)
		fmt.Fprintf(deps.stdout, "Downloading %s...\n", c.AssetName)
		gotSHA, err := downloadAndHash(deps.httpClient, c.DownloadURL, dest, maxReleasePkgBytes)
		if err != nil {
			return fmt.Errorf("download %s: %w", c.AssetName, err)
		}
		if !strings.EqualFold(gotSHA, c.RemoteSHA) {
			return fmt.Errorf("SHA-256 mismatch for %s: got %s, expected %s", c.AssetName, gotSHA, c.RemoteSHA)
		}
		fmt.Fprintf(deps.stdout, "Verified SHA-256 for %s (%s)\n", c.AssetName, shortSHA(gotSHA))
		downloaded = append(downloaded, dest)
	}

	if !*yes {
		fmt.Fprintf(deps.stdout, "Install %d verified package(s) via pacman -U? [y/N]: ", len(downloaded))
		line, err := bufio.NewReader(deps.stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read confirmation: %w", err)
		}
		ans := strings.ToLower(strings.TrimSpace(line))
		if ans != "y" && ans != "yes" {
			return errors.New("aborted by user")
		}
	}

	if err := deps.installPkgs(downloaded); err != nil {
		return fmt.Errorf("pacman -U failed: %w", err)
	}

	newState := releaseState{
		Tag:       rel.TagName,
		UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		Packages:  make(map[string]string, len(state.Packages)+len(toUpdate)),
	}
	for k, v := range state.Packages {
		newState.Packages[k] = v
	}
	for _, c := range toUpdate {
		newState.Packages[c.PkgName] = strings.ToLower(c.RemoteSHA)
	}
	if err := saveReleaseState(*statePath, newState); err != nil {
		return fmt.Errorf("save release state: %w", err)
	}

	fmt.Fprintf(deps.stdout, "Updated successfully to %s.\n", rel.TagName)
	return nil
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme == "https" && u.Host != "" {
		return nil
	}
	// Allow loopback HTTP strictly for local test servers.
	if u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost") {
		return nil
	}
	return fmt.Errorf("refusing non-HTTPS URL %q", raw)
}

func fetchGitHubRelease(client *http.Client, apiBase, repo, tag string) (*githubRelease, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/releases/latest", apiBase, repo)
	if tag != "" {
		endpoint = fmt.Sprintf("%s/repos/%s/releases/tags/%s", apiBase, repo, url.PathEscape(tag))
	}
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "fplogin-updater")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("query GitHub release: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GitHub API %s returned HTTP %d", endpoint, resp.StatusCode)
	}
	var rel githubRelease
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode GitHub release JSON: %w", err)
	}
	if rel.TagName == "" {
		return nil, errors.New("GitHub release response missing tag_name")
	}
	return &rel, nil
}

func findAssetByName(assets []githubReleaseAsset, name string) (githubReleaseAsset, bool) {
	for _, a := range assets {
		if a.Name == name {
			return a, true
		}
	}
	return githubReleaseAsset{}, false
}

func fetchSHA256Sums(client *http.Client, rawURL string) (map[string]string, error) {
	if err := validateURL(rawURL); err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "fplogin-updater")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSHA256SumsBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSHA256SumsBytes {
		return nil, errors.New("SHA256SUMS exceeds size limit")
	}
	return parseSHA256Sums(string(data))
}

func parseSHA256Sums(body string) (map[string]string, error) {
	sums := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("malformed SHA256SUMS line %q", line)
		}
		sum := strings.ToLower(fields[0])
		name := strings.TrimPrefix(fields[1], "*")
		if !sha256Pattern.MatchString(sum) {
			return nil, fmt.Errorf("invalid SHA-256 digest %q", fields[0])
		}
		if name == "" || strings.Contains(name, "/") || strings.Contains(name, "\\") || strings.Contains(name, "..") {
			return nil, fmt.Errorf("unsafe filename %q in SHA256SUMS", name)
		}
		sums[name] = sum
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(sums) == 0 {
		return nil, errors.New("SHA256SUMS is empty")
	}
	return sums, nil
}

func selectUpdateCandidates(
	assets []githubReleaseAsset,
	sums map[string]string,
	state releaseState,
	queryPacman func(pkg string) (string, bool),
) []updateCandidate {
	type pkgRule struct {
		name           string
		prefix         string
		onlyIfPresent  bool
	}
	rules := []pkgRule{
		{name: "fplogin-git", prefix: "fplogin-git-", onlyIfPresent: false},
		{name: "sddm-fplogin", prefix: "sddm-fplogin-", onlyIfPresent: true},
	}

	var out []updateCandidate
	for _, r := range rules {
		installedVer, installed := queryPacman(r.name)
		localSHA := strings.ToLower(state.Packages[r.name])
		if r.onlyIfPresent && !installed && localSHA == "" {
			continue
		}
		for _, a := range assets {
			if !strings.HasPrefix(a.Name, r.prefix) ||
				!strings.HasSuffix(a.Name, ".pkg.tar.zst") ||
				strings.Contains(a.Name, "-debug-") {
				continue
			}
			remoteSHA, ok := sums[a.Name]
			if !ok {
				continue
			}
			out = append(out, updateCandidate{
				PkgName:     r.name,
				AssetName:   a.Name,
				DownloadURL: a.BrowserDownloadURL,
				RemoteSHA:   remoteSHA,
				LocalSHA:    localSHA,
				Installed:   installedVer,
				Changed:     localSHA == "" || !strings.EqualFold(localSHA, remoteSHA),
			})
			break
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PkgName < out[j].PkgName })
	return out
}

func downloadAndHash(client *http.Client, rawURL, dest string, maxBytes int64) (string, error) {
	if err := validateURL(rawURL); err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "fplogin-updater")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, maxBytes+1))
	closeErr := f.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	if n > maxBytes {
		return "", fmt.Errorf("asset exceeds max size (%d bytes)", maxBytes)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func loadReleaseState(path string) (releaseState, error) {
	st := releaseState{Packages: map[string]string{}}
	fi, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return st, nil
		}
		return st, err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return st, fmt.Errorf("refusing symlink state file %s", path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return st, err
	}
	if err := json.Unmarshal(data, &st); err != nil {
		return st, err
	}
	if st.Packages == nil {
		st.Packages = map[string]string{}
	}
	return st, nil
}

func saveReleaseState(path string, st releaseState) error {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlink state file %s", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".release-state-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func shortSHA(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
