package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"fplogin/internal/descriptortrust"
	"fplogin/internal/platformclient"
	"fplogin/internal/protocol"
	v1 "fplogin/internal/protocol/platform/v1"
)

const (
	// systemTrust is the root-owned offline trust root for live installations
	// (candidate.gpg, optional candidate.fpr, pacman.conf, and public/ gpgdir).
	systemTrust = "/etc/fplogin/trust"
	// labTrust is only for the signed, offline F05/F06/F07 lab baseline.
	labTrust = "/etc/fplogin/f05-lab"
)

type trustConfig struct {
	dir          string
	isLab        bool
	candidateFpr string
}

var baselinePackages = map[string]string{
	stockArchive: "sddm 0.21.0-7",
	"675904869fa349291eddd348e47fa376b5e07dace2e3f8d86d3bf60390e31be0": "sddm-fplogin 0.21.0-3.1",
	"c772c6d18c29b58443cee96d9a6012baf8cb9622a14553e4759fdc418b93cf3c": "qt5-base 5.15.19+kde+r96-1",
	"8b207369843d9603a87420279ddacf025718dcdb47a7ea4ad703e4c70357ea78": "qt5-declarative 5.15.19+kde+r23-1",
	"d40691ffba09e2dae8da22b02db8aae76e700528f4954b4b0be00afa58876e11": "qt5-quickcontrols2 5.15.19+kde+r5-1",
	"874d631c937bbca955257cd47af9199864479a07772e99cc480775b1efb6ea1f": "qt5-svg 5.15.19+kde+r5-1",
	"5031b69a16673fa44d5d9285276960e8b6f93df38211a60977a288b661008c88": "qt5-translations 5.15.19-1",
}

func resolveTrust(op string) (trustConfig, error) {
	if _, err := os.Lstat(systemTrust); err == nil {
		if err := descriptortrust.ValidatePackagedDir(systemTrust); err != nil {
			return trustConfig{}, fmt.Errorf("unsafe trust directory %s: %w", systemTrust, err)
		}
		for _, f := range []string{"candidate.gpg", "pacman.conf"} {
			if err := descriptortrust.ValidatePackagedFile(filepath.Join(systemTrust, f)); err != nil {
				return trustConfig{}, fmt.Errorf("unsafe trust file %s: %w", f, err)
			}
		}
		if err := descriptortrust.ValidatePackagedDir(filepath.Join(systemTrust, "public")); err != nil {
			return trustConfig{}, fmt.Errorf("unsafe trust keyring dir: %w", err)
		}
		var fpr string
		fprPath := filepath.Join(systemTrust, "candidate.fpr")
		if _, err := os.Lstat(fprPath); err == nil {
			if err := descriptortrust.ValidatePackagedFile(fprPath); err != nil {
				return trustConfig{}, fmt.Errorf("unsafe candidate.fpr: %w", err)
			}
			b, err := os.ReadFile(fprPath)
			if err != nil {
				return trustConfig{}, err
			}
			fpr = strings.ToUpper(strings.TrimSpace(string(b)))
			if len(fpr) != 40 {
				return trustConfig{}, fmt.Errorf("invalid candidate.fpr length")
			}
		}
		return trustConfig{dir: systemTrust, isLab: false, candidateFpr: fpr}, nil
	}
	if _, err := os.Stat(labTrust + "/candidate.gpg"); err == nil {
		return trustConfig{dir: labTrust, isLab: true, candidateFpr: "CBFAD8C1A4FDE6D8FE5FA8F59911358499AA1EA6"}, nil
	}
	return trustConfig{}, notImplemented(op)
}

func labOutput(path string, args ...string) (string, error) {
	c := exec.Command(path, args...)
	c.Env = []string{"LC_ALL=C", "PATH=/usr/bin"}
	b, err := c.Output()
	return strings.TrimSpace(string(b)), err
}

func verifyStagedArchive(trust trustConfig, canonicalPath, digest string) (string, error) {
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
		return "", fmt.Errorf("staged archive digest mismatch for %s", digest)
	}

	var name string
	if trust.isLab {
		name = baselinePackages[digest]
		if name == "" {
			return "", fmt.Errorf("unexpected package archive %q", digest)
		}
	} else {
		out, err := labOutput("/usr/bin/pacman", "--config", "/dev/null", "-Qp", canonicalPath)
		if err != nil {
			return "", fmt.Errorf("inspect staged package %s: %w", digest, err)
		}
		fields := strings.Fields(out)
		if len(fields) != 2 || fields[0] == "" || fields[1] == "" {
			return "", fmt.Errorf("unexpected pacman -Qp output %q", out)
		}
		name = fields[0] + " " + fields[1]
	}

	key := "/etc/pacman.d/gnupg/pubring.gpg"
	signer := ""
	if trust.isLab {
		signer = "1519D5ABA65BF6FC2B73C7567A4E76095D8A52E4"
	}
	if strings.HasPrefix(name, "sddm-fplogin ") {
		key = filepath.Join(trust.dir, "candidate.gpg")
		signer = trust.candidateFpr
	}
	sig := canonicalPath + ".sig"
	st, err := os.Lstat(sig)
	if err != nil || !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > 65536 {
		return "", fmt.Errorf("invalid signature sidecar")
	}
	status, err := labOutput("/usr/bin/gpgv", "--keyring", key, "--status-fd", "1", sig, canonicalPath)
	if err != nil {
		return "", fmt.Errorf("signature rejected for %s", name)
	}
	want := "\n[GNUPG:] VALIDSIG "
	if signer != "" {
		want += signer + " "
	}
	if !strings.Contains("\n"+status, want) {
		return "", fmt.Errorf("signature rejected for %s", name)
	}
	return name, nil
}

func prepareLab(req v1.Request) (json.RawMessage, error) {
	var p v1.PrepareArtifactInstallPayload
	if err := json.Unmarshal(req.Payload, &p); err != nil {
		return nil, err
	}
	trust, err := resolveTrust(req.Operation)
	if err != nil {
		return nil, err
	}
	stage := p.StagingHandoff.Workspace
	if req.Context.Root != "/" || !strings.HasPrefix(stage, "/var/lib/fplogin/") || p.StagingHandoff.SourceCache != stage {
		return nil, fmt.Errorf("unexpected staging workspace %q", stage)
	}
	if trust.isLab && len(p.ArtifactReferences) != len(baselinePackages) && len(p.ArtifactReferences) != len(baselinePackages)-1 {
		return nil, fmt.Errorf("not a staged F05 baseline")
	}
	if len(p.ArtifactReferences) == 0 {
		return nil, fmt.Errorf("empty artifact set")
	}
	seen := map[string]bool{}
	ids := map[string]bool{}
	for _, r := range p.ArtifactReferences {
		if trust.isLab && baselinePackages[r.SHA256] == "" {
			return nil, fmt.Errorf("unexpected staged archive")
		}
		if seen[r.SHA256] || ids[r.ArtifactID] || r.CanonicalPath != filepath.Join(stage, r.SHA256) {
			return nil, fmt.Errorf("unexpected staged archive")
		}
		seen[r.SHA256] = true
		ids[r.ArtifactID] = true
	}
	if err := platformclient.ValidateArtifactFiles(p); err != nil {
		return nil, err
	}

	args := []string{"--config", filepath.Join(trust.dir, "pacman.conf"), "--gpgdir", filepath.Join(trust.dir, "public"), "-Up", "--print-format", "%n %v", "--"}
	var expected []string
	var result v1.ArtifactInstallPreparation
	seenPkg := map[string]string{}
	stockVer := ""
	candVer := ""
	for _, r := range p.ArtifactReferences {
		nameVer, err := verifyStagedArchive(trust, r.CanonicalPath, r.SHA256)
		if err != nil {
			return nil, err
		}
		pkgName, pkgVer, _ := strings.Cut(nameVer, " ")
		if seenPkg[pkgName] != "" {
			return nil, fmt.Errorf("duplicate staged package %q", pkgName)
		}
		seenPkg[pkgName] = pkgVer
		if pkgName == "sddm" {
			stockVer = pkgVer
		} else {
			if pkgName == "sddm-fplogin" {
				candVer = pkgVer
			}
			expected = append(expected, nameVer)
			args = append(args, r.CanonicalPath)
		}
		result.References = append(result.References, v1.PreparedArtifactReference{ArtifactID: r.ArtifactID, ProviderReference: r.SHA256, MediaType: r.MediaType, SHA256: r.SHA256, Size: r.Size, OperationParameters: protocol.Object{}})
	}
	if candVer == "" {
		return nil, fmt.Errorf("missing sddm-fplogin candidate archive")
	}

	inventory, err := labOutput("/usr/bin/pacman", "--config", "/dev/null", "-Q")
	if err != nil {
		return nil, fmt.Errorf("installed stock does not match rollback archive")
	}
	installed := map[string]string{}
	for _, line := range strings.Split(inventory, "\n") {
		if n, v, ok := strings.Cut(line, " "); ok && n != "" {
			installed[n] = v
		}
	}
	installedStockVer, hasStock := installed["sddm"]
	installedCandVer, hasCandidate := installed["sddm-fplogin"]
	if hasStock && (stockVer == "" || installedStockVer != stockVer) {
		return nil, fmt.Errorf("installed stock does not match rollback archive")
	}
	if hasCandidate && installedCandVer != candVer {
		return nil, fmt.Errorf("installed sddm-fplogin does not match approved candidate")
	}
	switch {
	case hasStock:
		if stockVer == "" {
			return nil, fmt.Errorf("stock sddm replacement requires matching stock rollback archive")
		}
		if err := checkStockFiles(); err != nil {
			return nil, err
		}
	case hasCandidate:
		if err := checkStockFiles(); err != nil {
			return nil, err
		}
	default:
		if stockVer != "" {
			return nil, fmt.Errorf("fresh no-stock install must not include stock sddm rollback archive")
		}
		if err := checkStockFilesAbsentOrIntact(); err != nil {
			return nil, err
		}
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
