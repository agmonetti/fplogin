// Package install implements the 13-phase installer orchestrator conforme to §8.1.
package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"fplogin/internal/core/discovery"
	"fplogin/internal/core/manifest"
	"fplogin/internal/core/transaction"
	"fplogin/internal/descriptortrust"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

var (
	ErrNoCompatibleTargets = errors.New("no compatible display manager targets detected")
	ErrPrerequisiteFailed  = errors.New("adapter prerequisite check failed")
	ErrApprovalRequired    = errors.New("explicit approval of the exact change plan is required")
	ErrPrivilegesRequired  = errors.New("only non-privileged isolated file transactions are supported")
	ErrVerificationFailed  = errors.New("post-installation verification failed")
	ErrTransactionAborted  = errors.New("installation transaction failed and was rolled back")
	ErrRecoveryRequired    = errors.New("installation transaction needs recovery")
)

// AdapterInvoker provides the adapter protocol methods needed by the installer.
type AdapterInvoker interface {
	Detect(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.DetectionReport, error)
	CheckPrerequisites(ctx context.Context, adapter discovery.Adapter, payload adapterv1.CheckPrerequisitesPayload, host protocol.HostContext) (adapterv1.PrerequisiteReport, error)
	InspectState(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.DisplayManagerState, error)
	PlanInstall(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.ChangePlan, error)
	PrepareArtifacts(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.ArtifactSet, error)
	Verify(ctx context.Context, adapter discovery.Adapter, host protocol.HostContext) (adapterv1.VerificationReport, error)
}

// PlatformInvoker provides platform operations needed by the installer.
type PlatformInvoker interface {
	PlatformApplier
	InspectHost(ctx context.Context, provider discovery.Provider, host protocol.HostContext) (platformv1.PlatformHostReport, error)
	PrepareArtifactInstall(ctx context.Context, provider discovery.Provider, payload platformv1.PrepareArtifactInstallPayload, host protocol.HostContext) error
}

// Config specifies the runtime configuration and dependencies for the installer.
type Config struct {
	AdapterDiscoverer  discovery.AdapterDiscoverer
	ProviderDiscoverer discovery.ProviderDiscoverer
	AdapterInvoker     AdapterInvoker
	PlatformInvoker    PlatformInvoker
	AdapterDirs        []string
	ProviderDirs       []string
	TargetDMID         string // Optional override from CLI (--target)
	DryRun             bool
	ApprovePlan        func(planDigest string, replacesDM bool) error
	JournalDir         string // defaults to /var/lib/fplogin/transactions
	ManifestPath       string // defaults to /var/lib/fplogin/manifest.json
	// IsolatedFiles is an exact destination allowlist supplied by the lab, never by an adapter.
	IsolatedFiles []string
	// IsolatedArchiveCache opts the lab into package preparation, never host mutation.
	IsolatedArchiveCache string
	Host                 protocol.HostContext
	CoreVersion          string
}

// Result captures the outcome of an installer run.
type Result struct {
	DryRun           bool                          `json:"dry_run"`
	Mode             string                        `json:"mode,omitempty"`
	TransactionID    string                        `json:"transaction_id,omitempty"`
	SelectedTarget   adapterv1.DetectedTarget      `json:"selected_target"`
	SelectedAdapter  discovery.Adapter             `json:"selected_adapter"`
	SelectedProvider discovery.Provider            `json:"selected_provider"`
	Plan             adapterv1.ChangePlan          `json:"plan"`
	AppliedReceipts  []manifestv1.OperationReceipt `json:"applied_receipts,omitempty"`
	ManifestPath     string                        `json:"manifest_path,omitempty"`
	JournalPath      string                        `json:"journal_path,omitempty"`
}

func rollbackAfterError(ctx context.Context, executor *Executor, cause error) error {
	if _, err := executor.Rollback(ctx); err != nil {
		return fmt.Errorf("%w: %w (rollback failed: %w)", ErrRecoveryRequired, cause, err)
	}
	return cause
}

func changePlanDigest(plan adapterv1.ChangePlan) (string, error) {
	data, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	return sha256Hex(data), nil
}

// Run executes the 13 phases of installation.
func Run(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.CoreVersion == "" {
		cfg.CoreVersion = "0.2.0"
	}
	if cfg.JournalDir == "" {
		cfg.JournalDir = "/var/lib/fplogin/transactions"
	}
	if cfg.ManifestPath == "" {
		cfg.ManifestPath = "/var/lib/fplogin/manifest.json"
	}

	stateRoot := filepath.Dir(cfg.JournalDir)
	var allowFile func(string) bool
	elevated := descriptortrust.Elevated()
	if elevated && (cfg.DryRun || !cfg.Host.Elevated || cfg.IsolatedArchiveCache == "" || stateRoot != systemStateRoot || len(cfg.IsolatedFiles) != 0) {
		return nil, ErrPrivilegesRequired
	}
	if !elevated && cfg.Host.Elevated {
		return nil, ErrPrivilegesRequired
	}
	var prevManifest *manifestv1.InstallManifest
	var prevMismatches []manifest.FileMismatch
	if !cfg.DryRun {
		if cfg.JournalDir != filepath.Join(stateRoot, "transactions") || cfg.ManifestPath != filepath.Join(stateRoot, "manifest.json") {
			return nil, errors.New("manifest and transactions must share the canonical transaction state root")
		}
		allowFile = filePolicy(stateRoot, cfg.IsolatedFiles)
		if allowFile == nil {
			return nil, ErrPrivilegesRequired
		}
		lock, err := transaction.AcquireLock(stateRoot)
		if err != nil {
			return nil, err
		}
		defer lock.Close()
		if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
			return nil, err
		}
		if loaded, loadErr := manifest.Load(cfg.ManifestPath); loadErr == nil {
			prevManifest = &loaded
			prevMismatches, err = manifest.VerifyFiles(loaded)
			if err != nil {
				return nil, fmt.Errorf("verify existing installation manifest: %w", err)
			}
		} else if !errors.Is(loadErr, manifest.ErrManifestNotFound) {
			return nil, loadErr
		}
	} else if loaded, loadErr := manifest.Load(cfg.ManifestPath); loadErr == nil {
		prevManifest = &loaded
		prevMismatches, _ = manifest.VerifyFiles(loaded)
	}

	// -------------------------------------------------------------------------
	// Fase 1: Detectar plataforma y host context
	// -------------------------------------------------------------------------
	discRes, err := discovery.Run(ctx, discovery.Config{
		AdapterDiscoverer:  cfg.AdapterDiscoverer,
		ProviderDiscoverer: cfg.ProviderDiscoverer,
		AdapterDirs:        cfg.AdapterDirs,
		ProviderDirs:       cfg.ProviderDirs,
		Host:               cfg.Host,
	})
	if err != nil {
		return nil, fmt.Errorf("phase 1 (discovery): %w", err)
	}

	selectedProvider := discRes.Provider

	// -------------------------------------------------------------------------
	// Fase 2 & 3: Obtener candidatos DM, detectar targets y seleccionar
	// -------------------------------------------------------------------------
	var selectedAdapter discovery.Adapter
	var selectedTarget adapterv1.DetectedTarget
	foundTarget := false

	for _, adapter := range discRes.Adapters {
		report, err := cfg.AdapterInvoker.Detect(ctx, adapter, cfg.Host)
		if err != nil {
			continue
		}
		for _, target := range report.Targets {
			if target.Compatibility != "compatible" {
				continue
			}
			if cfg.TargetDMID != "" && target.DMID != cfg.TargetDMID {
				continue
			}
			selectedAdapter = adapter
			selectedTarget = target
			foundTarget = true
			break
		}
		if foundTarget {
			break
		}
	}

	if !foundTarget {
		return nil, ErrNoCompatibleTargets
	}

	// -------------------------------------------------------------------------
	// Fase 4: Prerequisites y estado del DM
	// -------------------------------------------------------------------------
	prereqPayload := adapterv1.CheckPrerequisitesPayload{
		Target:                selectedTarget,
		RequestedCapabilities: []string{"biometric_auth"},
		Mode:                  preliminaryInstallMode(prevManifest, prevMismatches, selectedAdapter),
	}
	prereqReport, err := cfg.AdapterInvoker.CheckPrerequisites(ctx, selectedAdapter, prereqPayload, cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("phase 4 (prerequisites check): %w", err)
	}
	for _, finding := range prereqReport.Findings {
		if finding.Severity == "required" && finding.Status != "satisfied" {
			return nil, fmt.Errorf("%w: prerequisite %q is %s", ErrPrerequisiteFailed, finding.PrerequisiteID, finding.Status)
		}
	}

	dmState, err := cfg.AdapterInvoker.InspectState(ctx, selectedAdapter, cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("phase 4 (inspect state): %w", err)
	}

	// -------------------------------------------------------------------------
	// Fase 5: Change Plan completo (adapter-authored, core-validated)
	// -------------------------------------------------------------------------
	plan, err := cfg.AdapterInvoker.PlanInstall(ctx, selectedAdapter, cfg.Host)
	if err != nil {
		return nil, fmt.Errorf("phase 5 (plan install): %w", err)
	}
	if err := plan.Validate(); err != nil {
		return nil, fmt.Errorf("phase 5 (validate change plan): %w", err)
	}

	effectiveMode := classifyInstallMode(prevManifest, prevMismatches, selectedAdapter, plan)

	// Si es Dry-Run, terminamos aquí sin tocar journal ni mutar nada
	if cfg.DryRun {
		return &Result{
			DryRun:           true,
			Mode:             effectiveMode,
			SelectedTarget:   selectedTarget,
			SelectedAdapter:  selectedAdapter,
			SelectedProvider: selectedProvider,
			Plan:             plan,
		}, nil
	}

	// -------------------------------------------------------------------------
	// Fase 6: Barrera de aprobación explícita
	// -------------------------------------------------------------------------
	planBytes, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	// Freeze the approved content; later adapter calls cannot mutate this copy.
	plan, err = adapterv1.DecodeChangePlan(planBytes)
	if err != nil {
		return nil, err
	}
	if len(plan.Operations) == 0 {
		return nil, fmt.Errorf("%w: empty file plan", ErrPrecondition)
	}
	packagePlan := cfg.IsolatedArchiveCache != "" && len(plan.ArtifactReferences) != 0
	if packagePlan && cfg.PlatformInvoker == nil {
		return nil, fmt.Errorf("%w: platform provider is required for package transactions", ErrPrecondition)
	}
	isServiceOp := func(kind protocol.OperationKind) bool {
		return kind == protocol.SetServiceEnabled || kind == protocol.SetServiceActive || kind == protocol.RestoreServiceState
	}
	paths := make(map[string]bool, len(plan.Operations))
	firstService := len(plan.Operations)
	for i, op := range plan.Operations {
		if packagePlan && isServiceOp(op.Kind) {
			if firstService == len(plan.Operations) {
				firstService = i
			}
			continue
		}
		if firstService < len(plan.Operations) {
			return nil, fmt.Errorf("operation %q cannot follow service activation: %w", op.OperationID, ErrPrecondition)
		}
		if packagePlan && (op.Kind == protocol.InstallPackageArtifact || op.Kind == protocol.RemoveOwnedPackage) {
			continue
		}
		_, path, err := recoverableFile(op)
		if err != nil || !allowFile(path) || paths[path] {
			return nil, fmt.Errorf("operation %q requires a distinct allowed file destination: %w", op.OperationID, errors.Join(ErrPrecondition, err))
		}
		paths[path] = true
	}
	planDigest, err := changePlanDigest(plan)
	if err != nil {
		return nil, err
	}
	replacesDM := dmState.Active == "yes" || dmState.Enabled == "yes"
	if cfg.ApprovePlan == nil {
		return nil, ErrApprovalRequired
	}
	if err := cfg.ApprovePlan(planDigest, replacesDM); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrApprovalRequired, err)
	}

	// -------------------------------------------------------------------------
	// Fase 7: Persistir y fsync transaction journal ANTES de la mutación
	// -------------------------------------------------------------------------
	txID := fmt.Sprintf("tx-%d", time.Now().UnixNano())
	journalPath := filepath.Join(cfg.JournalDir, txID+".json")

	now := time.Now().UTC().Format(time.RFC3339)
	initJournal := manifestv1.TransactionJournal{
		SchemaVersion: manifestv1.SchemaVersion,
		FileRecovery:  true,
		TransactionID: txID,
		State:         "prepared",
		CreatedAt:     now,
		UpdatedAt:     now,
		Target: manifestv1.Target{
			InstanceID:  selectedTarget.InstanceID,
			DMID:        selectedTarget.DMID,
			DisplayName: selectedTarget.DisplayName,
		},
		Adapter: manifestv1.ComponentIdentity{
			ID:               selectedAdapter.Descriptor.AdapterID,
			Version:          selectedAdapter.Descriptor.AdapterVersion,
			ProtocolVersion:  selectedAdapter.ProtocolVersion,
			DescriptorSHA256: selectedAdapter.DescriptorSHA256,
		},
		PlatformProvider: manifestv1.ComponentIdentity{
			ID:               selectedProvider.Descriptor.PlatformID,
			Version:          selectedProvider.Descriptor.PlatformVersion,
			ProtocolVersion:  selectedProvider.ProtocolVersion,
			DescriptorSHA256: selectedProvider.DescriptorSHA256,
		},
		AcceptedPlan: manifestv1.AcceptedPlan{
			PlanID:     plan.PlanID,
			PlanDigest: planDigest,
			InputHash:  plan.InputHash,
			Mode:       effectiveMode,
		},
		AppliedOperations:   []manifestv1.OperationReceipt{},
		VerificationResults: []json.RawMessage{},
		RollbackRecords:     []json.RawMessage{},
	}

	if err := transaction.CheckNoUnresolved(cfg.JournalDir); err != nil {
		return nil, err
	}
	if err := persistApprovedPlan(stateRoot, txID, planDigest, plan); err != nil {
		return nil, fmt.Errorf("persist approved plan: %w", err)
	}
	var platform PlatformApplier
	if packagePlan {
		platform = cfg.PlatformInvoker
	}
	executor, err := beginTransaction(stateRoot, cfg.IsolatedFiles, initJournal, plan.Operations, platform)
	if err != nil {
		return nil, err
	}
	if packagePlan {
		payload, prepErr := stageApprovedArchives(stateRoot, txID, cfg.IsolatedArchiveCache)
		if prepErr == nil {
			prepErr = cfg.PlatformInvoker.PrepareArtifactInstall(ctx, selectedProvider, payload, cfg.Host)
		}
		if prepErr != nil {
			if err := executor.Journal.AbortPrepared(); err != nil {
				return nil, errors.Join(ErrRecoveryRequired, prepErr, err)
			}
			return nil, fmt.Errorf("package transaction stopped before mutation: %w", prepErr)
		}
	}

	// -------------------------------------------------------------------------
	// Fase 9a: Aplicar paquetes y archivos tipados; journalizar cada resultado
	// -------------------------------------------------------------------------
	var appliedReceipts []manifestv1.OperationReceipt
	executeOps := func(ops []protocol.Operation) error {
		for _, op := range ops {
			receipt, execErr := executor.Execute(ctx, op)
			if execErr != nil {
				return fmt.Errorf("operation %q failed: %w", op.OperationID, execErr)
			}
			appliedReceipts = append(appliedReceipts, receipt)
		}
		return nil
	}

	if mutationErr := executeOps(plan.Operations[:firstService]); mutationErr != nil {
		// Rollback compensatorio
		rbReceipts, rbErr := executor.Rollback(ctx)
		if rbErr != nil {
			return nil, fmt.Errorf("%w: %w (rollback also failed: %w)", ErrRecoveryRequired, mutationErr, rbErr)
		}
		return nil, fmt.Errorf("%w: %w (compensated %d operations)", ErrTransactionAborted, mutationErr, len(rbReceipts))
	}

	// -------------------------------------------------------------------------
	// Fase 10: Verificación del adapter ANTES de habilitar/activar el servicio
	// -------------------------------------------------------------------------
	verifyReport, err := cfg.AdapterInvoker.Verify(ctx, selectedAdapter, cfg.Host)
	if err != nil {
		return nil, rollbackAfterError(ctx, executor, fmt.Errorf("%w: %w", ErrVerificationFailed, err))
	}
	for _, chk := range verifyReport.Checks {
		if chk.Severity == "required" && chk.Status != "passed" {
			return nil, rollbackAfterError(ctx, executor, fmt.Errorf("%w: check %q status is %s", ErrVerificationFailed, chk.CheckID, chk.Status))
		}
	}
	verifyRaw := make([]json.RawMessage, 0, len(verifyReport.Checks)+1)
	for _, chk := range verifyReport.Checks {
		raw, marshalErr := json.Marshal(chk)
		if marshalErr != nil {
			return nil, rollbackAfterError(ctx, executor, marshalErr)
		}
		verifyRaw = append(verifyRaw, raw)
	}
	if len(verifyRaw) == 0 {
		raw, _ := json.Marshal(map[string]any{"report_id": verifyReport.ReportID, "status": "passed"})
		verifyRaw = append(verifyRaw, raw)
	}
	if err := executor.Journal.RecordVerification(verifyRaw, true); err != nil {
		return nil, fmt.Errorf("%w: record verification for transaction %q: %w", ErrRecoveryRequired, txID, err)
	}

	// -------------------------------------------------------------------------
	// Fase 9b: Aplicar operaciones de servicio solo tras verificación exitosa
	// -------------------------------------------------------------------------
	if mutationErr := executeOps(plan.Operations[firstService:]); mutationErr != nil {
		rbReceipts, rbErr := executor.Rollback(ctx)
		if rbErr != nil {
			return nil, fmt.Errorf("%w: %w (rollback also failed: %w)", ErrRecoveryRequired, mutationErr, rbErr)
		}
		return nil, fmt.Errorf("%w: %w (compensated %d operations)", ErrTransactionAborted, mutationErr, len(rbReceipts))
	}

	// -------------------------------------------------------------------------
	// Fase 11 & 12: Publicar manifiesto durable y completar el journal
	// -------------------------------------------------------------------------
	installedManifest, err := buildInstallManifest(
		cfg, txID, effectiveMode, planDigest, selectedTarget, selectedAdapter,
		selectedProvider, dmState, plan, appliedReceipts, verifyReport, prevManifest, packagePlan,
	)
	if err != nil {
		return nil, rollbackAfterError(ctx, executor, fmt.Errorf("build install manifest: %w", err))
	}
	if testBeforeManifestPublish != nil {
		testBeforeManifestPublish(txID)
	}
	if err := manifest.Publish(cfg.ManifestPath, installedManifest); err != nil {
		return nil, fmt.Errorf("%w: publish manifest for transaction %q: %w", ErrRecoveryRequired, txID, err)
	}
	if testAfterManifestPublish != nil {
		testAfterManifestPublish(txID)
	}
	if err := executor.Journal.Checkpoint(); err != nil {
		return nil, fmt.Errorf("%w: complete transaction %q: %w", ErrRecoveryRequired, txID, err)
	}

	// -------------------------------------------------------------------------
	// Fase 13: Reporte de resultados
	// -------------------------------------------------------------------------
	return &Result{
		DryRun:           false,
		Mode:             effectiveMode,
		TransactionID:    txID,
		SelectedTarget:   selectedTarget,
		SelectedAdapter:  selectedAdapter,
		SelectedProvider: selectedProvider,
		Plan:             plan,
		AppliedReceipts:  appliedReceipts,
		ManifestPath:     cfg.ManifestPath,
		JournalPath:      journalPath,
	}, nil
}
