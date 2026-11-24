package install

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

// stageApprovedArchives runs under the transaction lock. cache is a core-selected,
// trusted directory keyed by digest, never an adapter-provided source path.
// This snapshots bytes only; it does not certify package identity or signatures.
func stageApprovedArchives(stateRoot, txID, cache string) (platformv1.PrepareArtifactInstallPayload, error) {
	var p platformv1.PrepareArtifactInstallPayload
	plan, err := loadApprovedPlan(stateRoot, txID)
	if err != nil {
		return p, err
	}
	digest, err := changePlanDigest(plan)
	if err != nil {
		return p, err
	}
	if len(plan.ArtifactReferences) == 0 {
		return p, fmt.Errorf("no approved archives")
	}
	used := map[string]bool{}
	ids := []string{}
	for _, op := range plan.Operations {
		if op.Kind != protocol.InstallPackageArtifact && op.Kind != protocol.RemoveOwnedPackage {
			continue
		}
		ids = append(ids, op.OperationID)
		if op.Kind == protocol.InstallPackageArtifact {
			var pkg protocol.PackageArtifactParameters
			if err := json.Unmarshal(op.Parameters, &pkg); err != nil {
				return p, err
			}
			used[pkg.ArtifactID] = true
		}
		undo, err := approvedPackageUndo(op)
		if err != nil {
			return p, err
		}
		if undo.Kind == protocol.InstallPackageArtifact {
			var stock protocol.PackageArtifactParameters
			if err := json.Unmarshal(undo.Parameters, &stock); err != nil {
				return p, err
			}
			used[stock.ArtifactID] = true
		}
	}
	for _, ref := range plan.ArtifactReferences {
		if !used[ref.ArtifactID] {
			return p, fmt.Errorf("unconsumed approved archive %q", ref.ArtifactID)
		}
	}
	dir, err := transaction.OpenBackupDir(stateRoot, txID)
	if err != nil {
		return p, err
	}
	stage := filepath.Join(dir, "archives")
	if err = os.Mkdir(stage, 0700); err != nil {
		return p, err
	}
	refs := make([]platformv1.ArtifactReference, 0, len(plan.ArtifactReferences))
	for _, ref := range plan.ArtifactReferences {
		dst := filepath.Join(stage, ref.SHA256)
		if err := snapshotArchive(cache, dst, ref.SHA256, ref.Size); err != nil {
			return p, fmt.Errorf("stage %q: %w", ref.ArtifactID, err)
		}
		if err := snapshotSignature(filepath.Join(cache, ref.SHA256+".sig"), dst+".sig"); err != nil {
			return p, fmt.Errorf("stage signature %q: %w", ref.ArtifactID, err)
		}
		refs = append(refs, platformv1.ArtifactReference{ArtifactID: ref.ArtifactID, MediaType: ref.MediaType, SHA256: ref.SHA256, Size: ref.Size, Role: ref.Role, CanonicalPath: dst})
	}
	for _, path := range []string{stage, dir} {
		d, err := os.Open(path)
		if err != nil {
			return p, err
		}
		err = d.Sync()
		d.Close()
		if err != nil {
			return p, err
		}
	}

	return platformv1.PrepareArtifactInstallPayload{PlanDigest: digest, ArtifactReferences: refs, SelectedCapabilities: plan.ExpectedCapabilities, OperationIDs: ids, StagingHandoff: platformv1.StagingHandoff{Workspace: stage, SourceCache: stage}}, nil
}

// The sidecar is untrusted until the provider verifies it against its own keyring.
func snapshotSignature(src, dst string) error {
	const max = 64 << 10
	f, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() <= 0 || st.Size() > max {
		return fmt.Errorf("invalid detached signature file")
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return err
	}
	if int64(len(b)) != st.Size() {
		return fmt.Errorf("signature size changed")
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	if _, err = out.Write(b); err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func snapshotArchive(cache, dst, digest string, size int64) error {
	if err := protocol.ValidDigest(digest); err != nil {
		return err
	}
	src, err := os.OpenFile(filepath.Join(cache, digest), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer src.Close()
	st, err := src.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() != size {
		return fmt.Errorf("archive type or size mismatch")
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		return err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(src, size))
	if err == nil && (n != size || fmt.Sprintf("%x", h.Sum(nil)) != digest) {
		err = fmt.Errorf("archive digest mismatch")
	}
	if err == nil {
		err = out.Sync()
	}
	closeErr := out.Close()
	if err != nil {
		return err
	}
	return closeErr
}
