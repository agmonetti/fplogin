package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"fplogin/internal/platformclient"
	"fplogin/internal/protocol"
	v1 "fplogin/internal/protocol/platform/v1"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// This policy is only for the signed, offline F05 baseline. The lab supplies
// its public keyring independently of the transaction, never from the adapter.
const labTrust = "/etc/fplogin/f05-lab"

var baselinePackages = map[string]string{
	stockArchive: "sddm 0.21.0-7",
	"675904869fa349291eddd348e47fa376b5e07dace2e3f8d86d3bf60390e31be0": "sddm-fplogin 0.21.0-3.1",
	"c772c6d18c29b58443cee96d9a6012baf8cb9622a14553e4759fdc418b93cf3c": "qt5-base 5.15.19+kde+r96-1",
	"8b207369843d9603a87420279ddacf025718dcdb47a7ea4ad703e4c70357ea78": "qt5-declarative 5.15.19+kde+r23-1",
	"d40691ffba09e2dae8da22b02db8aae76e700528f4954b4b0be00afa58876e11": "qt5-quickcontrols2 5.15.19+kde+r5-1",
	"874d631c937bbca955257cd47af9199864479a07772e99cc480775b1efb6ea1f": "qt5-svg 5.15.19+kde+r5-1",
	"5031b69a16673fa44d5d9285276960e8b6f93df38211a60977a288b661008c88": "qt5-translations 5.15.19-1",
}

func labOutput(path string, args ...string) (string, error) {
	c := exec.Command(path, args...)
	c.Env = []string{"LC_ALL=C", "PATH=/usr/bin"}
	b, err := c.Output()
	return strings.TrimSpace(string(b)), err
}

func verifyStagedArchive(canonicalPath, digest string) (string, error) {
	name := baselinePackages[digest]
	if name == "" {
		return "", fmt.Errorf("unexpected package archive %q", digest)
	}
	if canonicalPath == "" || filepath.Clean(canonicalPath) != canonicalPath ||
		!strings.HasPrefix(canonicalPath, "/var/lib/fplogin/") || filepath.Base(canonicalPath) != digest {
		return "", fmt.Errorf("unexpected staged archive path %q", canonicalPath)
	}
	f, err := os.OpenFile(canonicalPath, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 {
		return "", fmt.Errorf("invalid staged archive %q", canonicalPath)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if fmt.Sprintf("%x", h.Sum(nil)) != digest {
		return "", fmt.Errorf("staged archive digest mismatch for %s", name)
	}
	key := "/etc/pacman.d/gnupg/pubring.gpg"
	signer := "1519D5ABA65BF6FC2B73C7567A4E76095D8A52E4"
	if strings.HasPrefix(name, "sddm-fplogin ") {
		key = labTrust + "/candidate.gpg"
		signer = "CBFAD8C1A4FDE6D8FE5FA8F59911358499AA1EA6"
	}
	sig := canonicalPath + ".sig"
	st, err := os.Lstat(sig)
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 65536 {
		return "", fmt.Errorf("invalid signature sidecar")
	}
	status, err := labOutput("/usr/bin/gpgv", "--keyring", key, "--status-fd", "1", sig, canonicalPath)
	if err != nil || !strings.Contains("\n"+status, "\n[GNUPG:] VALIDSIG "+signer+" ") {
		return "", fmt.Errorf("signature rejected for %s", name)
	}
	return name, nil
}

func prepareLab(req v1.Request) (json.RawMessage, error) {
	var p v1.PrepareArtifactInstallPayload
	if err := json.Unmarshal(req.Payload, &p); err != nil {
		return nil, err
	}
	if _, err := os.Stat(labTrust + "/candidate.gpg"); err != nil {
		return nil, notImplemented(req.Operation)
	}
	stage := p.StagingHandoff.Workspace
	if req.Context.Root != "/" || !strings.HasPrefix(stage, "/var/lib/fplogin/") || p.StagingHandoff.SourceCache != stage || len(p.ArtifactReferences) != len(baselinePackages) {
		return nil, fmt.Errorf("not a staged F05 baseline")
	}
	seen := map[string]bool{}
	ids := map[string]bool{}
	args := []string{"--config", labTrust + "/pacman.conf", "--gpgdir", labTrust + "/public", "-Up", "--print-format", "%n %v", "--"}
	var expected []string
	var result v1.ArtifactInstallPreparation
	for _, r := range p.ArtifactReferences {
		name := baselinePackages[r.SHA256]
		if name == "" || seen[r.SHA256] || ids[r.ArtifactID] || r.CanonicalPath != filepath.Join(stage, r.SHA256) {
			return nil, fmt.Errorf("unexpected staged archive")
		}
		seen[r.SHA256] = true
		ids[r.ArtifactID] = true
	}
	if err := platformclient.ValidateArtifactFiles(p); err != nil {
		return nil, err
	}
	for _, r := range p.ArtifactReferences {
		name, err := verifyStagedArchive(r.CanonicalPath, r.SHA256)
		if err != nil {
			return nil, err
		}
		if r.SHA256 != stockArchive {
			expected = append(expected, name)
			args = append(args, r.CanonicalPath)
		}
		result.References = append(result.References, v1.PreparedArtifactReference{ArtifactID: r.ArtifactID, ProviderReference: r.SHA256, MediaType: r.MediaType, SHA256: r.SHA256, Size: r.Size, OperationParameters: protocol.Object{}})
	}
	inventory, err := labOutput("/usr/bin/pacman", "--config", "/dev/null", "-Q")
	if err != nil {
		return nil, fmt.Errorf("installed stock does not match rollback archive")
	}
	const candidateArchive = "675904869fa349291eddd348e47fa376b5e07dace2e3f8d86d3bf60390e31be0"
	invLines := "\n" + inventory + "\n"
	if !strings.Contains(invLines, "\n"+baselinePackages[stockArchive]+"\n") &&
		!strings.Contains(invLines, "\n"+baselinePackages[candidateArchive]+"\n") {
		return nil, fmt.Errorf("installed stock does not match rollback archive")
	}
	if err := checkStockFiles(); err != nil {
		return nil, err
	}
	out, err := labOutput("/usr/bin/pacman", args...)
	actual := strings.Split(out, "\n")
	sort.Strings(actual)
	sort.Strings(expected)
	if err != nil {
		return nil, fmt.Errorf("offline package resolution: %w", err)
	}
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return nil, fmt.Errorf("offline package resolution differs from approved set")
	}
	return json.Marshal(result)
}
