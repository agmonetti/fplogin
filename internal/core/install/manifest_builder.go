package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"fplogin/internal/core/discovery"
	"fplogin/internal/core/manifest"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	manifestv1 "fplogin/internal/protocol/manifest/v1"
)

func preliminaryInstallMode(prev *manifestv1.InstallManifest, mismatches []manifest.FileMismatch, adapter discovery.Adapter) string {
	if prev == nil {
		return "fresh_install"
	}
	if len(mismatches) > 0 {
		return "repair"
	}
	if adapter.Descriptor.AdapterVersion != prev.Adapter.Version {
		return "upgrade"
	}
	return "reinstall"
}

func classifyInstallMode(prev *manifestv1.InstallManifest, mismatches []manifest.FileMismatch, adapter discovery.Adapter, plan adapterv1.ChangePlan) string {
	if prev == nil {
		return "fresh_install"
	}
	if len(mismatches) > 0 || plan.Mode == "repair" {
		return "repair"
	}
	if plan.Mode == "upgrade" || adapter.Descriptor.AdapterVersion != prev.Adapter.Version {
		return "upgrade"
	}

	prevFiles := make(map[string]string, len(prev.InstalledFiles))
	for _, f := range prev.InstalledFiles {
		prevFiles[f.Path] = f.SHA256
	}
	prevPkgs := make(map[string]string, len(prev.InstalledPackages))
	for _, p := range prev.InstalledPackages {
		prevPkgs[p.PackageReference] = p.SHA256
	}

	for _, op := range plan.Operations {
		switch op.Kind {
		case protocol.WriteFileAtomic:
			params, path, err := recoverableFile(op)
			if err != nil {
				continue
			}
			if oldHash, ok := prevFiles[path]; !ok || oldHash != params.SHA256 {
				return "upgrade"
			}
		case protocol.InstallPackageArtifact:
			var params protocol.PackageArtifactParameters
			if err := json.Unmarshal(op.Parameters, &params); err != nil {
				continue
			}
			if oldHash, ok := prevPkgs[params.PackageReference]; !ok || (oldHash != "" && oldHash != params.SHA256) {
				return "upgrade"
			}
		}
	}
	return "reinstall"
}

func buildInstallManifest(
	cfg Config,
	txID string,
	effectiveMode string,
	planDigest string,
	target adapterv1.DetectedTarget,
	adapter discovery.Adapter,
	provider discovery.Provider,
	dmState adapterv1.DisplayManagerState,
	plan adapterv1.ChangePlan,
	receipts []manifestv1.OperationReceipt,
	verifyReport adapterv1.VerificationReport,
	prev *manifestv1.InstallManifest,
	archivesStaged bool,
) (manifestv1.InstallManifest, error) {
	now := time.Now().UTC().Format(time.RFC3339)

	artifactRoles := make(map[string]string, len(plan.ArtifactReferences))
	for _, ref := range plan.ArtifactReferences {
		artifactRoles[ref.ArtifactID] = ref.Role
	}
	opByID := make(map[string]protocol.Operation, len(plan.Operations))
	for _, op := range plan.Operations {
		opByID[op.OperationID] = op
	}

	installedFiles := []manifestv1.InstalledFile{}
	installedPkgs := []manifestv1.InstalledPackage{}
	enabledServices := []string{}
	disabledServices := []string{}
	priorServiceOrder := []string{}
	priorServiceMap := map[string]*manifestv1.ServiceState{}

	baselineFiles := []manifestv1.BaselineFile{}
	baselinePkgs := []manifestv1.BaselinePackage{}

	touchPriorService := func(name string) *manifestv1.ServiceState {
		if st, ok := priorServiceMap[name]; ok {
			return st
		}
		st := &manifestv1.ServiceState{
			ServiceReference: name,
			Enabled:          "unknown",
			Active:           "unknown",
		}
		priorServiceMap[name] = st
		priorServiceOrder = append(priorServiceOrder, name)
		return st
	}

	for _, r := range receipts {
		op := opByID[r.OperationID]
		switch r.Kind {
		case protocol.WriteFileAtomic:
			before, err := manifestv1.DecodeFileState(r.BeforeState)
			if err != nil {
				return manifestv1.InstallManifest{}, fmt.Errorf("decode before file state for %q: %w", r.OperationID, err)
			}
			installed, err := inspectInstalledFile(before.Path)
			if err != nil {
				return manifestv1.InstallManifest{}, fmt.Errorf("inspect installed file %q: %w", before.Path, err)
			}
			installedFiles = append(installedFiles, installed)

			bf := manifestv1.BaselineFile{Path: before.Path, Existed: before.Exists}
			if before.Exists {
				bf.SHA256 = before.SHA256
				bf.Mode = before.Mode
				bf.BackupTxID = txID
				bf.BackupOpID = r.OperationID
			}
			baselineFiles = append(baselineFiles, bf)

		case protocol.InstallPackageArtifact:
			var params protocol.PackageArtifactParameters
			if err := json.Unmarshal(op.Parameters, &params); err != nil {
				return manifestv1.InstallManifest{}, fmt.Errorf("decode package params for %q: %w", r.OperationID, err)
			}
			ver := decodeJSONString(r.AfterState["version"])
			if ver == "" {
				ver = "unknown"
			}
			pkg := manifestv1.InstalledPackage{
				PackageReference: params.PackageReference,
				Version:          ver,
				SHA256:           params.SHA256,
			}
			if archivesStaged {
				pkg.StageTxID = txID
			}
			installedPkgs = append(installedPkgs, pkg)

			role := artifactRoles[params.ArtifactID]
			bp := manifestv1.BaselinePackage{
				PackageReference:    params.PackageReference,
				InstalledArtifactID: params.ArtifactID,
				InstalledSHA256:     params.SHA256,
				SharedDependency:    role == "shared_dependency" || role == "dependency",
				ExistedBefore:       decodeJSONBool(r.BeforeState["installed"]),
			}
			if archivesStaged {
				bp.StageTxID = txID
			}
			if comp, err := protocol.DecodePackageCompensation(op.Kind, op.Compensation); err == nil {
				if comp.Kind == "install_package" && comp.PackageReference != params.PackageReference {
					bp.ReplacedPackageReference = comp.PackageReference
					bp.ReplacedArtifactID = comp.ArtifactID
					bp.ReplacedSHA256 = comp.SHA256
					bp.SharedDependency = false
					bp.ExistedBefore = false
				}
			}
			baselinePkgs = append(baselinePkgs, bp)

		case protocol.SetServiceEnabled:
			var params struct {
				ServiceReference string `json:"service_reference"`
				Enabled          bool   `json:"enabled"`
			}
			if err := json.Unmarshal(op.Parameters, &params); err != nil {
				return manifestv1.InstallManifest{}, fmt.Errorf("decode service enabled params for %q: %w", r.OperationID, err)
			}
			if params.Enabled {
				enabledServices = appendUnique(enabledServices, params.ServiceReference)
			} else {
				disabledServices = appendUnique(disabledServices, params.ServiceReference)
			}
			st := touchPriorService(params.ServiceReference)
			if st.Enabled == "unknown" {
				st.Enabled = boolTriState(r.BeforeState["enabled"])
			}

		case protocol.SetServiceActive:
			var params struct {
				ServiceReference string `json:"service_reference"`
				Active           bool   `json:"active"`
			}
			if err := json.Unmarshal(op.Parameters, &params); err != nil {
				return manifestv1.InstallManifest{}, fmt.Errorf("decode service active params for %q: %w", r.OperationID, err)
			}
			st := touchPriorService(params.ServiceReference)
			if st.Active == "unknown" {
				st.Active = boolTriState(r.BeforeState["active"])
			}

		case protocol.RestoreServiceState:
			var params struct {
				ServiceReference string `json:"service_reference"`
				Enabled          string `json:"enabled"`
				Active           string `json:"active"`
			}
			if err := json.Unmarshal(op.Parameters, &params); err != nil {
				return manifestv1.InstallManifest{}, fmt.Errorf("decode restore service params for %q: %w", r.OperationID, err)
			}
			if params.Enabled == "yes" {
				enabledServices = appendUnique(enabledServices, params.ServiceReference)
			} else if params.Enabled == "no" {
				disabledServices = appendUnique(disabledServices, params.ServiceReference)
			}
			st := touchPriorService(params.ServiceReference)
			if st.Enabled == "unknown" {
				st.Enabled = stringTriState(r.BeforeState["enabled"])
			}
			if st.Active == "unknown" {
				st.Active = stringTriState(r.BeforeState["active"])
			}
		}
	}

	priorStates := make([]manifestv1.ServiceState, 0, len(priorServiceOrder))
	for _, name := range priorServiceOrder {
		priorStates = append(priorStates, *priorServiceMap[name])
	}

	prevDM := manifestv1.PreviousDMState{
		ServiceName: "none",
		Enabled:     triOrUnknown(dmState.Enabled),
		Active:      triOrUnknown(dmState.Active),
	}
	if len(disabledServices) > 0 {
		if st, ok := priorServiceMap[disabledServices[0]]; ok {
			prevDM = manifestv1.PreviousDMState{
				ServiceName: st.ServiceReference,
				Enabled:     st.Enabled,
				Active:      st.Active,
			}
		}
	} else if len(enabledServices) > 0 {
		if st, ok := priorServiceMap[enabledServices[0]]; ok {
			prevDM = manifestv1.PreviousDMState{
				ServiceName: st.ServiceReference,
				Enabled:     st.Enabled,
				Active:      st.Active,
			}
		}
	}

	var baseline manifestv1.RecoveryBaseline
	if prev != nil && prev.RecoveryBaseline != nil {
		baseline = mergeRecoveryBaseline(*prev.RecoveryBaseline, baselineFiles, baselinePkgs, priorStates)
		prevDM = baseline.PreviousDMState
		priorStates = append([]manifestv1.ServiceState(nil), baseline.Services...)
		installedFiles = mergeInstalledFiles(prev.InstalledFiles, installedFiles)
		installedPkgs = mergeInstalledPackages(prev.InstalledPackages, installedPkgs)
		for _, svc := range prev.Services.Enabled {
			if !containsString(disabledServices, svc) {
				enabledServices = appendUnique(enabledServices, svc)
			}
		}
		for _, svc := range prev.Services.Disabled {
			if !containsString(enabledServices, svc) {
				disabledServices = appendUnique(disabledServices, svc)
			}
		}
	} else {
		baseline = manifestv1.RecoveryBaseline{
			BaselineTransactionID: txID,
			RecordedAt:            now,
			Files:                 baselineFiles,
			Packages:              baselinePkgs,
			Services:              priorStates,
			PreviousDMState:       prevDM,
		}
	}

	// Build verification summary from adapter VerificationReport.
	checks := make([]manifestv1.VerificationCheck, 0, len(verifyReport.Checks))
	for _, c := range verifyReport.Checks {
		ev := make([]json.RawMessage, 0, len(c.Evidence))
		for _, item := range c.Evidence {
			raw, err := json.Marshal(item)
			if err != nil {
				return manifestv1.InstallManifest{}, err
			}
			ev = append(ev, raw)
		}
		checks = append(checks, manifestv1.VerificationCheck{
			CheckID:  c.CheckID,
			Status:   c.Status,
			Evidence: ev,
			Message:  c.Message,
		})
	}
	verifiedAt := verifyReport.VerifiedAt
	if verifiedAt == "" {
		verifiedAt = now
	}
	reportID := verifyReport.ReportID
	if reportID == "" {
		reportID = "verify-" + txID
	}

	caps := append([]string(nil), plan.ExpectedCapabilities...)
	if caps == nil {
		caps = []string{}
	}

	m := manifestv1.InstallManifest{
		SchemaVersion:  manifestv1.SchemaVersion,
		TransactionID:  txID,
		FPLoginVersion: cfg.CoreVersion,
		InstalledAt:    now,
		Target: manifestv1.Target{
			InstanceID:  target.InstanceID,
			DMID:        target.DMID,
			DisplayName: target.DisplayName,
		},
		Adapter: manifestv1.AdapterIdentity{
			ComponentIdentity: manifestv1.ComponentIdentity{
				ID:               adapter.Descriptor.AdapterID,
				Version:          adapter.Descriptor.AdapterVersion,
				ProtocolVersion:  adapter.ProtocolVersion,
				DescriptorSHA256: adapter.DescriptorSHA256,
			},
			InstalledCapabilities: caps,
		},
		PlatformProvider: manifestv1.ComponentIdentity{
			ID:               provider.Descriptor.PlatformID,
			Version:          provider.Descriptor.PlatformVersion,
			ProtocolVersion:  provider.ProtocolVersion,
			DescriptorSHA256: provider.DescriptorSHA256,
		},
		AcceptedPlan: manifestv1.AcceptedPlan{
			PlanID:     plan.PlanID,
			PlanDigest: planDigest,
			InputHash:  plan.InputHash,
			Mode:       effectiveMode,
		},
		InstalledFiles:    installedFiles,
		InstalledPackages: installedPkgs,
		Services: manifestv1.Services{
			Enabled:     enabledServices,
			Disabled:    disabledServices,
			PriorStates: priorStates,
		},
		PreviousDMState:   prevDM,
		OperationReceipts: receipts,
		Verification: manifestv1.Verification{
			ReportID:   reportID,
			VerifiedAt: verifiedAt,
			Checks:     checks,
		},
		RecoveryBaseline: &baseline,
	}
	return m, m.Validate()
}

// mergeRecoveryBaseline preserves the original recovery record intact across
// reinstall, upgrade, and repair runs, only appending genuinely new items.
func mergeRecoveryBaseline(
	orig manifestv1.RecoveryBaseline,
	newFiles []manifestv1.BaselineFile,
	newPkgs []manifestv1.BaselinePackage,
	newServices []manifestv1.ServiceState,
) manifestv1.RecoveryBaseline {
	merged := manifestv1.RecoveryBaseline{
		BaselineTransactionID: orig.BaselineTransactionID,
		RecordedAt:            orig.RecordedAt,
		Files:                 append([]manifestv1.BaselineFile(nil), orig.Files...),
		Packages:              append([]manifestv1.BaselinePackage(nil), orig.Packages...),
		Services:              append([]manifestv1.ServiceState(nil), orig.Services...),
		PreviousDMState:       orig.PreviousDMState,
	}
	seenFiles := make(map[string]bool, len(orig.Files))
	for _, f := range orig.Files {
		seenFiles[f.Path] = true
	}
	for _, f := range newFiles {
		if !seenFiles[f.Path] {
			merged.Files = append(merged.Files, f)
			seenFiles[f.Path] = true
		}
	}
	seenPkgs := make(map[string]bool, len(orig.Packages))
	for _, p := range orig.Packages {
		seenPkgs[p.PackageReference] = true
	}
	for _, p := range newPkgs {
		if !seenPkgs[p.PackageReference] {
			merged.Packages = append(merged.Packages, p)
			seenPkgs[p.PackageReference] = true
		}
	}
	seenSvcs := make(map[string]bool, len(orig.Services))
	for _, s := range orig.Services {
		seenSvcs[s.ServiceReference] = true
	}
	for _, s := range newServices {
		if !seenSvcs[s.ServiceReference] {
			merged.Services = append(merged.Services, s)
			seenSvcs[s.ServiceReference] = true
		}
	}
	return merged
}

func inspectInstalledFile(path string) (manifestv1.InstalledFile, error) {
	data, mode, err := readOrdinaryFile(path)
	if err != nil {
		return manifestv1.InstalledFile{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return manifestv1.InstalledFile{}, err
	}
	st := info.Sys().(*syscall.Stat_t)
	return manifestv1.InstalledFile{
		Path:   path,
		SHA256: sha256Hex(data),
		Mode:   fmt.Sprintf("%04o", mode),
		Owner:  uidName(st.Uid),
		Group:  gidName(st.Gid),
		Size:   int64(len(data)),
	}, nil
}

func uidName(uid uint32) string {
	if uid == 0 {
		return "root"
	}
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil && u.Username != "" {
		return u.Username
	}
	return id
}

func gidName(gid uint32) string {
	if gid == 0 {
		return "root"
	}
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(id); err == nil && g.Name != "" {
		return g.Name
	}
	return id
}

func decodeJSONString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func decodeJSONBool(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false
	}
	return b
}

func boolTriState(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "unknown"
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return stringTriState(raw)
	}
	if b {
		return "yes"
	}
	return "no"
}

func stringTriState(raw json.RawMessage) string {
	s := decodeJSONString(raw)
	if s == "yes" || s == "no" || s == "unknown" {
		return s
	}
	return "unknown"
}

func triOrUnknown(s string) string {
	if s == "yes" || s == "no" {
		return s
	}
	return "unknown"
}

func appendUnique(items []string, value string) []string {
	for _, existing := range items {
		if existing == value {
			return items
		}
	}
	return append(items, value)
}

func containsString(items []string, value string) bool {
	for _, existing := range items {
		if existing == value {
			return true
		}
	}
	return false
}

func mergeInstalledFiles(prev, current []manifestv1.InstalledFile) []manifestv1.InstalledFile {
	byPath := make(map[string]manifestv1.InstalledFile, len(current))
	for _, f := range current {
		byPath[f.Path] = f
	}
	out := make([]manifestv1.InstalledFile, 0, len(prev)+len(current))
	seen := make(map[string]bool, len(prev)+len(current))
	for _, f := range prev {
		if updated, ok := byPath[f.Path]; ok {
			out = append(out, updated)
		} else {
			out = append(out, f)
		}
		seen[f.Path] = true
	}
	for _, f := range current {
		if !seen[f.Path] {
			out = append(out, f)
		}
	}
	return out
}

func mergeInstalledPackages(prev, current []manifestv1.InstalledPackage) []manifestv1.InstalledPackage {
	byRef := make(map[string]manifestv1.InstalledPackage, len(current))
	for _, p := range current {
		byRef[p.PackageReference] = p
	}
	out := make([]manifestv1.InstalledPackage, 0, len(prev)+len(current))
	seen := make(map[string]bool, len(prev)+len(current))
	for _, p := range prev {
		if updated, ok := byRef[p.PackageReference]; ok {
			out = append(out, updated)
		} else {
			out = append(out, p)
		}
		seen[p.PackageReference] = true
	}
	for _, p := range current {
		if !seen[p.PackageReference] {
			out = append(out, p)
		}
	}
	return out
}
