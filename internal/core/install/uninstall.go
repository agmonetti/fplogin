package install

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"fplogin/internal/core/manifest"
	"fplogin/internal/core/transaction"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

// ModifiedFilePolicy controls how Uninstall handles installed files whose
// on-disk checksum differs from the manifest.
type ModifiedFilePolicy string

const (
	// ModifiedFilePreserve leaves locally modified files untouched while still
	// restoring unmodified files, packages, and services.
	ModifiedFilePreserve ModifiedFilePolicy = "preserve"
	// ModifiedFileRefuse aborts uninstall before any mutation if any installed
	// file was modified locally.
	ModifiedFileRefuse ModifiedFilePolicy = "refuse"
	// ModifiedFileRestore explicitly approves overwriting or removing locally
	// modified files back to the recorded pre-fplogin baseline.
	ModifiedFileRestore ModifiedFilePolicy = "restore"
)

// UninstallConfig specifies parameters for transactional, adapter-independent uninstall.
type UninstallConfig struct {
	StateRoot                string
	ManifestPath             string
	JournalDir               string
	IsolatedFiles            []string
	Platform                 PlatformApplier
	ModifiedFiles            ModifiedFilePolicy
	RemoveSharedDependencies bool
	ApproveUninstall         func(planDigest string) error
}

// UninstallResult summarizes a completed transactional uninstall.
type UninstallResult struct {
	TransactionID      string                        `json:"transaction_id"`
	JournalPath        string                        `json:"journal_path"`
	AppliedReceipts    []manifestv1.OperationReceipt `json:"applied_receipts"`
	PreservedFiles     []string                      `json:"preserved_files,omitempty"`
	KeptSharedPackages []string                      `json:"kept_shared_packages,omitempty"`
}

// Unexported hooks for deterministic crash/interruption testing around manifest commit points.
var (
	testBeforeManifestPublish func(txID string)
	testAfterManifestPublish  func(txID string)
	testBeforeManifestRemove  func(txID string)
	testAfterManifestRemove   func(txID string)
)

// Uninstall restores the pre-fplogin recovery baseline recorded in the durable
// manifest through the transaction engine, without requiring the original adapter.
func Uninstall(ctx context.Context, cfg UninstallConfig) (*UninstallResult, error) {
	stateRoot := cfg.StateRoot
	if stateRoot == "" && cfg.ManifestPath != "" {
		stateRoot = filepath.Dir(cfg.ManifestPath)
	}
	if stateRoot == "" {
		stateRoot = systemStateRoot
	}
	manifestPath := cfg.ManifestPath
	if manifestPath == "" {
		manifestPath = filepath.Join(stateRoot, "manifest.json")
	}
	journalDir := cfg.JournalDir
	if journalDir == "" {
		journalDir = filepath.Join(stateRoot, "transactions")
	}
	if journalDir != filepath.Join(stateRoot, "transactions") || manifestPath != filepath.Join(stateRoot, "manifest.json") {
		return nil, errors.New("manifest and transactions must share the canonical transaction state root")
	}

	elevated := descriptortrust.Elevated()
	if elevated && (stateRoot != systemStateRoot || len(cfg.IsolatedFiles) != 0) {
		return nil, ErrPrivilegesRequired
	}
	allowFile := filePolicy(stateRoot, cfg.IsolatedFiles)
	if allowFile == nil {
		return nil, ErrPrivilegesRequired
	}

	policy := cfg.ModifiedFiles
	if policy == "" {
		policy = ModifiedFilePreserve
	}
	if policy != ModifiedFilePreserve && policy != ModifiedFileRefuse && policy != ModifiedFileRestore {
		return nil, fmt.Errorf("%w: unsupported modified file policy %q", ErrPrecondition, policy)
	}

	lock, err := transaction.AcquireLock(stateRoot)
	if err != nil {
		return nil, err
	}
	defer lock.Close()

	if err := transaction.CheckNoUnresolved(journalDir); err != nil {
		return nil, err
	}

	m, err := manifest.Load(manifestPath)
	if err != nil {
		return nil, err
	}
	if m.RecoveryBaseline == nil {
		return nil, fmt.Errorf("%w: manifest is missing recovery_baseline", manifest.ErrCorruptManifest)
	}

	mismatches, err := manifest.VerifyFiles(m)
	if err != nil {
		return nil, fmt.Errorf("verify installed files: %w", err)
	}
	mismatchByPath := make(map[string]manifest.FileMismatch, len(mismatches))
	var modifiedPaths []string
	for _, mm := range mismatches {
		mismatchByPath[mm.Path] = mm
		if mm.Kind == "modified" {
			modifiedPaths = append(modifiedPaths, mm.Path)
		}
	}
	if len(modifiedPaths) > 0 && policy == ModifiedFileRefuse {
		return nil, fmt.Errorf("%w: %v", manifest.ErrModifiedFiles, modifiedPaths)
	}

	ops, refs, archiveSources, preservedFiles, keptShared, err := buildUninstallPlan(stateRoot, m, mismatchByPath, policy, cfg.RemoveSharedDependencies)
	if err != nil {
		return nil, err
	}

	// Verify file destinations and platform requirement before approval or journaling.
	for _, op := range ops {
		if manifestv1.IsRecoverableFileKind(op.Kind) {
			_, path, err := recoverableFile(op)
			if err != nil || !allowFile(path) {
				return nil, fmt.Errorf("uninstall operation %q target not allowed: %w", op.OperationID, errors.Join(ErrPrecondition, err))
			}
		} else if cfg.Platform == nil {
			return nil, fmt.Errorf("%w: platform provider is required to restore packages or services", ErrPrecondition)
		}
	}

	now := time.Now().UTC().Format(time.RFC3339)
	txID := fmt.Sprintf("tx-uninstall-%d", time.Now().UnixNano())
	plan := adapterv1.ChangePlan{
		PlanID:               "uninstall-" + txID,
		AdapterID:            m.Adapter.ID,
		AdapterVersion:       m.Adapter.Version,
		ProtocolVersion:      m.Adapter.ProtocolVersion,
		TargetInstanceID:     m.Target.InstanceID,
		Mode:                 "uninstall",
		CreatedAt:            now,
		InputHash:            m.AcceptedPlan.PlanDigest,
		CanonicalPlanDigest:  m.AcceptedPlan.PlanDigest,
		Approvals:            []adapterv1.Approval{},
		Preconditions:        []adapterv1.Condition{},
		Postconditions:       []adapterv1.Condition{},
		ArtifactReferences:   refs,
		Operations:           ops,
		ExpectedCapabilities: []string{},
	}
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("validate uninstall plan: %w", err)
	}
	planDigest, err := changePlanDigest(plan)
	if err != nil {
		return nil, err
	}
	if cfg.ApproveUninstall != nil {
		if err := cfg.ApproveUninstall(planDigest); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrApprovalRequired, err)
		}
	}

	if err := persistApprovedPlan(stateRoot, txID, planDigest, plan); err != nil {
		return nil, fmt.Errorf("persist approved uninstall plan: %w", err)
	}
	if len(archiveSources) > 0 {
		if err := stageUninstallArchives(stateRoot, txID, archiveSources); err != nil {
			return nil, fmt.Errorf("stage uninstall rollback archives: %w", err)
		}
	}

	initJournal := manifestv1.TransactionJournal{
		SchemaVersion:    manifestv1.SchemaVersion,
		FileRecovery:     true,
		TransactionID:    txID,
		State:            "prepared",
		CreatedAt:        now,
		UpdatedAt:        now,
		Target:           m.Target,
		Adapter:          m.Adapter.ComponentIdentity,
		PlatformProvider: m.PlatformProvider,
		AcceptedPlan: manifestv1.AcceptedPlan{
			PlanID:     plan.PlanID,
			PlanDigest: planDigest,
			InputHash:  plan.InputHash,
			Mode:       "uninstall",
		},
		AppliedOperations:   []manifestv1.OperationReceipt{},
		VerificationResults: []json.RawMessage{},
		RollbackRecords:     []json.RawMessage{},
	}

	executor, err := beginTransaction(stateRoot, cfg.IsolatedFiles, initJournal, ops, cfg.Platform)
	if err != nil {
		return nil, err
	}

	var appliedReceipts []manifestv1.OperationReceipt
	for _, op := range ops {
		receipt, execErr := executor.Execute(ctx, op)
		if execErr != nil {
			rbReceipts, rbErr := executor.Rollback(ctx)
			if rbErr != nil {
				return nil, fmt.Errorf("%w: uninstall operation %q failed: %w (rollback also failed: %w)", ErrRecoveryRequired, op.OperationID, execErr, rbErr)
			}
			return nil, fmt.Errorf("%w: uninstall operation %q failed: %w (compensated %d operations; manifest preserved)", ErrTransactionAborted, op.OperationID, execErr, len(rbReceipts))
		}
		appliedReceipts = append(appliedReceipts, receipt)
	}

	if testBeforeManifestRemove != nil {
		testBeforeManifestRemove(txID)
	}
	if err := manifest.Remove(manifestPath); err != nil {
		return nil, fmt.Errorf("%w: remove manifest for uninstall %q: %w", ErrRecoveryRequired, txID, err)
	}
	if testAfterManifestRemove != nil {
		testAfterManifestRemove(txID)
	}
	if err := executor.Journal.Checkpoint(); err != nil {
		return nil, fmt.Errorf("%w: complete uninstall transaction %q: %w", ErrRecoveryRequired, txID, err)
	}

	return &UninstallResult{
		TransactionID:      txID,
		JournalPath:        executor.Journal.Path(),
		AppliedReceipts:    appliedReceipts,
		PreservedFiles:     preservedFiles,
		KeptSharedPackages: keptShared,
	}, nil
}

type stagedArchiveSource struct {
	digest     string
	sourceDirs []string
}

func buildUninstallPlan(
	stateRoot string,
	m manifestv1.InstallManifest,
	mismatchByPath map[string]manifest.FileMismatch,
	policy ModifiedFilePolicy,
	removeSharedDeps bool,
) ([]protocol.Operation, []adapterv1.ArtifactReference, []stagedArchiveSource, []string, []string, error) {
	baseline := m.RecoveryBaseline
	ops := []protocol.Operation{}
	refsByID := map[string]adapterv1.ArtifactReference{}
	var archiveSources []stagedArchiveSource
	addedArchives := map[string]bool{}
	var preservedFiles []string
	var keptShared []string

	installedFileMeta := make(map[string]manifestv1.InstalledFile, len(m.InstalledFiles))
	for _, f := range m.InstalledFiles {
		installedFileMeta[f.Path] = f
	}
	installedPkgMeta := make(map[string]manifestv1.InstalledPackage, len(m.InstalledPackages))
	for _, p := range m.InstalledPackages {
		installedPkgMeta[p.PackageReference] = p
	}

	addArchiveRef := func(artifactID, digest string, stageTxIDs ...string) error {
		var dirs []string
		var size int64
		for _, id := range stageTxIDs {
			if id == "" {
				continue
			}
			dir := filepath.Join(stateRoot, "backups", id, "archives")
			dirs = append(dirs, dir)
			if st, err := os.Stat(filepath.Join(dir, digest)); err == nil && st.Mode().IsRegular() {
				size = st.Size()
			}
		}
		if _, exists := refsByID[artifactID]; !exists {
			refsByID[artifactID] = adapterv1.ArtifactReference{
				ArtifactID:    artifactID,
				MediaType:     "application/octet-stream",
				SHA256:        digest,
				Size:          size,
				Role:          "package",
				CanonicalPath: "/var/lib/fplogin/archives/" + digest,
			}
		}
		if len(dirs) > 0 && !addedArchives[digest] {
			archiveSources = append(archiveSources, stagedArchiveSource{digest: digest, sourceDirs: dirs})
			addedArchives[digest] = true
		}
		return nil
	}

	serviceCompState := func(svc manifestv1.ServiceState) (string, string) {
		en := "unknown"
		if slices.Contains(m.Services.Enabled, svc.ServiceReference) {
			en = "yes"
		} else if slices.Contains(m.Services.Disabled, svc.ServiceReference) {
			en = "no"
		} else if svc.Enabled == "no" {
			en = "yes"
		} else if svc.Enabled == "yes" {
			en = "no"
		}
		act := "unknown"
		if svc.Active == "no" {
			act = "yes"
		} else if svc.Active == "yes" {
			act = "no"
		}
		return en, act
	}

	makeRestoreServiceOp := func(opID string, svc manifestv1.ServiceState) protocol.Operation {
		compEn, compAct := serviceCompState(svc)
		before := protocol.Object{}
		if compEn != "unknown" {
			before["enabled"] = json.RawMessage(fmt.Sprintf("%q", compEn))
		}
		if compAct != "unknown" {
			before["active"] = json.RawMessage(fmt.Sprintf("%q", compAct))
		}
		after := protocol.Object{}
		if svc.Enabled != "unknown" {
			after["enabled"] = json.RawMessage(fmt.Sprintf("%q", svc.Enabled))
		}
		if svc.Active != "unknown" {
			after["active"] = json.RawMessage(fmt.Sprintf("%q", svc.Active))
		}
		params, _ := json.Marshal(map[string]string{
			"service_reference": svc.ServiceReference,
			"enabled":           svc.Enabled,
			"active":            svc.Active,
		})
		comp, _ := json.Marshal(map[string]string{
			"kind":              "restore_service_state",
			"service_reference": svc.ServiceReference,
			"enabled":           compEn,
			"active":            compAct,
		})
		return protocol.Operation{
			OperationID:    opID,
			Kind:           protocol.RestoreServiceState,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: before,
			ExpectedAfter:  after,
			Parameters:     params,
			Compensation:   comp,
		}
	}

	// Phase 1: Disable/stop services that baseline wants disabled/inactive while units still exist.
	for i := len(baseline.Services) - 1; i >= 0; i-- {
		svc := baseline.Services[i]
		if svc.Enabled == "no" || svc.Active == "no" {
			ops = append(ops, makeRestoreServiceOp(fmt.Sprintf("uninstall-svc-stop-%d", i), svc))
		}
	}

	// Phase 2: Restore prior files or remove newly created owned files (preserve locally modified files by default).
	for i := len(baseline.Files) - 1; i >= 0; i-- {
		bf := baseline.Files[i]
		mm, hasMM := mismatchByPath[bf.Path]
		if hasMM && mm.Kind == "modified" && policy == ModifiedFilePreserve {
			preservedFiles = append(preservedFiles, bf.Path)
			continue
		}
		if !bf.Existed {
			data, _, err := readOrdinaryFile(bf.Path)
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, nil, nil, nil, nil, fmt.Errorf("inspect file %q for removal: %w", bf.Path, err)
			}
			actualHash := sha256Hex(data)
			params, _ := json.Marshal(map[string]string{
				"path":            bf.Path,
				"expected_sha256": actualHash,
			})
			comp, _ := json.Marshal(map[string]string{
				"kind":   "restore_file",
				"path":   bf.Path,
				"sha256": actualHash,
			})
			ops = append(ops, protocol.Operation{
				OperationID:    fmt.Sprintf("uninstall-file-rm-%d", i),
				Kind:           protocol.RemoveOwnedFile,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{},
				ExpectedAfter:  protocol.Object{},
				Parameters:     params,
				Compensation:   comp,
			})
			continue
		}

		// Originally existed: verify durable baseline backup and restore bytes & mode.
		backupPath := filepath.Join(stateRoot, "backups", bf.BackupTxID, sha256Hex([]byte(bf.BackupOpID))+".bak")
		origData, err := verifyBackup(backupPath, bf.SHA256)
		if err != nil {
			return nil, nil, nil, nil, nil, fmt.Errorf("verify baseline backup for %q: %w", bf.Path, err)
		}
		owner, group := "root", "root"
		if meta, ok := installedFileMeta[bf.Path]; ok && meta.Owner != "" && meta.Group != "" {
			owner, group = meta.Owner, meta.Group
		}
		params, _ := json.Marshal(map[string]string{
			"destination_path": bf.Path,
			"content_base64":   base64.StdEncoding.EncodeToString(origData),
			"sha256":           bf.SHA256,
			"mode":             bf.Mode,
			"owner":            owner,
			"group":            group,
		})
		comp, _ := json.Marshal(map[string]string{
			"kind": "restore_file",
			"path": bf.Path,
		})
		ops = append(ops, protocol.Operation{
			OperationID:    fmt.Sprintf("uninstall-file-restore-%d", i),
			Kind:           protocol.WriteFileAtomic,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{},
			ExpectedAfter:  protocol.Object{},
			Parameters:     params,
			Compensation:   comp,
		})
	}

	// Phase 3: Restore replaced packages and remove owned non-shared packages (keep shared dependencies by default).
	for i := len(baseline.Packages) - 1; i >= 0; i-- {
		bp := baseline.Packages[i]
		pkgMeta := installedPkgMeta[bp.PackageReference]
		curSHA := pkgMeta.SHA256
		if curSHA == "" {
			curSHA = bp.InstalledSHA256
		}
		curArtID := bp.InstalledArtifactID
		if curArtID == "" {
			curArtID = bp.PackageReference
		}

		if bp.ReplacedPackageReference != "" {
			if curSHA == "" {
				return nil, nil, nil, nil, nil, fmt.Errorf("missing installed package digest for rollback of %q", bp.PackageReference)
			}
			_ = addArchiveRef(bp.ReplacedArtifactID, bp.ReplacedSHA256, bp.StageTxID)
			_ = addArchiveRef(curArtID, curSHA, pkgMeta.StageTxID, m.TransactionID, bp.StageTxID)
			params, _ := json.Marshal(protocol.PackageArtifactParameters{
				PackageReference: bp.ReplacedPackageReference,
				ArtifactID:       bp.ReplacedArtifactID,
				SHA256:           bp.ReplacedSHA256,
			})
			comp, _ := json.Marshal(protocol.PackageCompensation{
				Kind: "install_package",
				PackageArtifactParameters: protocol.PackageArtifactParameters{
					PackageReference: bp.PackageReference,
					ArtifactID:       curArtID,
					SHA256:           curSHA,
				},
			})
			ops = append(ops, protocol.Operation{
				OperationID:    fmt.Sprintf("uninstall-pkg-restore-%d", i),
				Kind:           protocol.InstallPackageArtifact,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"installed": json.RawMessage(`false`)},
				ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`true`)},
				Parameters:     params,
				Compensation:   comp,
			})
			continue
		}

		if bp.ExistedBefore {
			continue
		}
		if bp.SharedDependency && !removeSharedDeps {
			keptShared = append(keptShared, bp.PackageReference)
			continue
		}
		if curSHA == "" {
			return nil, nil, nil, nil, nil, fmt.Errorf("missing installed package digest for removal of %q", bp.PackageReference)
		}
		_ = addArchiveRef(curArtID, curSHA, pkgMeta.StageTxID, m.TransactionID, bp.StageTxID)
		params, _ := json.Marshal(map[string]string{"package_reference": bp.PackageReference})
		comp, _ := json.Marshal(protocol.PackageCompensation{
			Kind: "install_package",
			PackageArtifactParameters: protocol.PackageArtifactParameters{
				PackageReference: bp.PackageReference,
				ArtifactID:       curArtID,
				SHA256:           curSHA,
			},
		})
		ops = append(ops, protocol.Operation{
			OperationID:    fmt.Sprintf("uninstall-pkg-rm-%d", i),
			Kind:           protocol.RemoveOwnedPackage,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"installed": json.RawMessage(`true`)},
			ExpectedAfter:  protocol.Object{"installed": json.RawMessage(`false`)},
			Parameters:     params,
			Compensation:   comp,
		})
	}

	// Phase 4: Re-enable/start prior DM or services that baseline had enabled/active.
	for i, svc := range baseline.Services {
		if svc.Enabled == "yes" || svc.Active == "yes" {
			ops = append(ops, makeRestoreServiceOp(fmt.Sprintf("uninstall-svc-restore-%d", i), svc))
		}
	}

	refs := make([]adapterv1.ArtifactReference, 0, len(refsByID))
	for _, ref := range refsByID {
		refs = append(refs, ref)
	}
	return ops, refs, archiveSources, preservedFiles, keptShared, nil
}

func stageUninstallArchives(stateRoot, txID string, sources []stagedArchiveSource) error {
	dir, err := transaction.OpenBackupDir(stateRoot, txID)
	if err != nil {
		return err
	}
	stage := filepath.Join(dir, "archives")
	if err := os.Mkdir(stage, 0o700); err != nil {
		return err
	}
	for _, src := range sources {
		var foundDir string
		var size int64
		for _, candidate := range src.sourceDirs {
			if st, err := os.Stat(filepath.Join(candidate, src.digest)); err == nil && st.Mode().IsRegular() {
				foundDir = candidate
				size = st.Size()
				break
			}
		}
		if foundDir == "" {
			return fmt.Errorf("missing preserved archive %q in backup directories", src.digest)
		}
		dst := filepath.Join(stage, src.digest)
		if err := snapshotArchive(foundDir, dst, src.digest, size); err != nil {
			return err
		}
		if err := snapshotSignature(filepath.Join(foundDir, src.digest+".sig"), dst+".sig"); err != nil {
			return err
		}
	}
	for _, p := range []string{stage, dir} {
		if err := syncDir(p); err != nil {
			return err
		}
	}
	return nil
}
