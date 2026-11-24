//go:build f05lab

package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"fplogin/internal/core/manifest"
	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
)

type f07Options struct {
	noDM             bool
	stockEnabled     bool
	withPriorGreetd  bool
	startSDDM        bool
	refuseReplaceDM  bool
	preinstalledPkgs []string
}

func buildF07LabFixture(t *testing.T, opts f07Options) (Config, *fakeAdapterInvoker, *labPlatform) {
	t.Helper()
	cfg, ad, lp := buildLabFixture(t)
	lpPtr := &lp
	cfg.PlatformInvoker = lpPtr

	// Mark qt5-* packages as shared dependencies and sddm-fplogin as DM package.
	filteredRefs := make([]adapterv1.ArtifactReference, 0, len(ad.plan.ArtifactReferences))
	for _, ref := range ad.plan.ArtifactReferences {
		if opts.noDM && ref.ArtifactID == "sddm" {
			continue
		}
		if strings.HasPrefix(ref.ArtifactID, "qt5-") {
			ref.Role = "shared_dependency"
		} else if ref.ArtifactID == "sddm-fplogin" {
			ref.Role = "display_manager_package"
		}
		filteredRefs = append(filteredRefs, ref)
	}
	ad.plan.ArtifactReferences = filteredRefs

	if opts.noDM || len(opts.preinstalledPkgs) > 0 {
		preinstalled := map[string]bool{}
		for _, pkg := range opts.preinstalledPkgs {
			preinstalled["pkg-"+pkg] = true
		}
		for i := range ad.plan.Operations {
			if opts.noDM && ad.plan.Operations[i].OperationID == "pkg-sddm-fplogin" {
				ad.plan.Operations[i].Compensation = json.RawMessage(`{"kind":"remove_package","package_reference":"sddm-fplogin"}`)
			}
			if preinstalled[ad.plan.Operations[i].OperationID] {
				ad.plan.Operations[i].ExpectedBefore = protocol.Object{"installed": json.RawMessage(`true`)}
			}
		}
	}

	// Build service operations (always strictly after packages and files).
	var svcOps []protocol.Operation
	if opts.withPriorGreetd {
		ad.dmState.Enabled = "yes"
		ad.dmState.Active = "yes"
		svcOps = append(svcOps,
			protocol.Operation{
				OperationID:    "stop-greetd",
				Kind:           protocol.SetServiceActive,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"active": json.RawMessage(`true`)},
				ExpectedAfter:  protocol.Object{"active": json.RawMessage(`false`)},
				Parameters:     json.RawMessage(`{"service_reference":"greetd.service","active":false}`),
				Compensation:   json.RawMessage(`{"kind":"set_service_active","service_reference":"greetd.service","active":true}`),
			},
			protocol.Operation{
				OperationID:    "disable-greetd",
				Kind:           protocol.SetServiceEnabled,
				Dependencies:   []string{},
				Preconditions:  []json.RawMessage{},
				ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`true`)},
				ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`false`)},
				Parameters:     json.RawMessage(`{"service_reference":"greetd.service","enabled":false}`),
				Compensation:   json.RawMessage(`{"kind":"set_service_enabled","service_reference":"greetd.service","enabled":true}`),
			},
		)
	}

	// Keep existing enable-sddm (last op from buildLabFixture) and optionally add start-sddm.
	enableOp := ad.plan.Operations[len(ad.plan.Operations)-1]
	if opts.stockEnabled {
		enableOp.ExpectedBefore = protocol.Object{"enabled": json.RawMessage(`true`)}
		enableOp.Compensation = json.RawMessage(`{"kind":"set_service_enabled","service_reference":"sddm.service","enabled":true}`)
	}
	svcOps = append(svcOps, enableOp)
	if opts.startSDDM {
		svcOps = append(svcOps, protocol.Operation{
			OperationID:    "start-sddm",
			Kind:           protocol.SetServiceActive,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"active": json.RawMessage(`false`)},
			ExpectedAfter:  protocol.Object{"active": json.RawMessage(`true`)},
			Parameters:     json.RawMessage(`{"service_reference":"sddm.service","active":true}`),
			Compensation:   json.RawMessage(`{"kind":"set_service_active","service_reference":"sddm.service","active":false}`),
		})
	}
	ad.plan.Operations = append(ad.plan.Operations[:len(ad.plan.Operations)-1], svcOps...)

	if opts.refuseReplaceDM {
		cfg.ApprovePlan = func(_ string, replacesDM bool) error {
			if replacesDM {
				return errors.New("owner refused display manager replacement")
			}
			return nil
		}
	}

	return cfg, ad, lpPtr
}

func assertServiceActiveState(t *testing.T, unit, want string) {
	t.Helper()
	out, _ := exec.Command("/usr/bin/systemctl", "is-active", unit).CombinedOutput()
	got := strings.TrimSpace(string(out))
	if got != want {
		t.Fatalf("expected %s is-active=%q, got %q", unit, want, got)
	}
}

func TestF07GuestLifecycle(t *testing.T) {
	mode := os.Getenv("F07_CASE")
	if mode == "" {
		t.Skip("F07_CASE not set")
	}
	ctx := context.Background()

	switch mode {
	// --- Scenario 1: No display manager ---
	case "no-dm-pkg-fail":
		cfg, _, _ := buildF07LabFixture(t, f07Options{noDM: true, startSDDM: true})
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("expected ErrTransactionAborted on package hook failure, got %v", err)
		}
		if _, err := os.Stat(cfg.ManifestPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest should not exist after rollback: %v", err)
		}

	case "no-dm-verify-fail":
		cfg, ad, _ := buildF07LabFixture(t, f07Options{noDM: true, startSDDM: true})
		ad.verifyReport.Checks[0].Status = "failed"
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("expected ErrVerificationFailed, got %v", err)
		}
		if _, err := os.Stat(cfg.ManifestPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest should not exist after verification rollback: %v", err)
		}

	case "no-dm-svc-fail":
		cfg, _, lp := buildF07LabFixture(t, f07Options{noDM: true, startSDDM: true})
		lp.failOpID = "start-sddm"
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("expected ErrTransactionAborted on service failure, got %v", err)
		}
		if _, err := os.Stat(cfg.ManifestPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest should not exist after service rollback: %v", err)
		}

	case "no-dm-install":
		cfg, _, _ := buildF07LabFixture(t, f07Options{noDM: true, startSDDM: true})
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("no-dm fresh install failed: %v", err)
		}
		if res.Mode != "fresh_install" {
			t.Fatalf("expected fresh_install, got %q", res.Mode)
		}
		m, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatalf("manifest missing: %v", err)
		}
		if m.RecoveryBaseline == nil || len(m.InstalledPackages) != 6 {
			t.Fatalf("unexpected manifest: %+v", m)
		}
		assertServiceEnabledState(t, "sddm.service", "enabled")
		assertServiceActiveState(t, "sddm.service", "active")

	case "no-dm-uninstall":
		_, _, lp := buildF07LabFixture(t, f07Options{noDM: true})
		if _, err := Uninstall(ctx, UninstallConfig{
			StateRoot:                systemStateRoot,
			Platform:                 lp,
			RemoveSharedDependencies: true,
		}); err != nil {
			t.Fatalf("no-dm uninstall failed: %v", err)
		}
		if _, err := os.Stat(systemStateRoot + "/manifest.json"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest still exists: %v", err)
		}

	// --- Scenario 2: Stock SDDM ---
	case "stock-svc-fail":
		cfg, _, lp := buildF07LabFixture(t, f07Options{stockEnabled: true, startSDDM: true})
		lp.failOpID = "start-sddm"
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("expected ErrTransactionAborted on stock service failure, got %v", err)
		}
		assertServiceEnabledState(t, "sddm.service", "enabled")
		assertServiceActiveState(t, "sddm.service", "inactive")
		if _, err := os.Stat(cfg.ManifestPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest should not exist after rollback: %v", err)
		}

	case "stock-install":
		cfg, _, _ := buildF07LabFixture(t, f07Options{stockEnabled: true, startSDDM: true})
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("stock install failed: %v", err)
		}
		if res.Mode != "fresh_install" {
			t.Fatalf("expected fresh_install, got %q", res.Mode)
		}
		assertServiceEnabledState(t, "sddm.service", "enabled")
		assertServiceActiveState(t, "sddm.service", "active")

	case "stock-uninstall":
		_, _, lp := buildF07LabFixture(t, f07Options{})
		if _, err := Uninstall(ctx, UninstallConfig{
			StateRoot:                systemStateRoot,
			Platform:                 lp,
			RemoveSharedDependencies: true,
		}); err != nil {
			t.Fatalf("stock uninstall failed: %v", err)
		}
		assertServiceEnabledState(t, "sddm.service", "enabled")
		assertServiceActiveState(t, "sddm.service", "inactive")

	// --- Scenario 3: Another enabled display manager (greetd) ---
	case "greetd-refuse":
		cfg, _, _ := buildF07LabFixture(t, f07Options{withPriorGreetd: true, startSDDM: true, refuseReplaceDM: true})
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrApprovalRequired) {
			t.Fatalf("expected ErrApprovalRequired on refused DM replacement, got %v", err)
		}
		assertServiceEnabledState(t, "greetd.service", "enabled")
		assertServiceActiveState(t, "greetd.service", "active")

	case "greetd-svc-fail":
		cfg, _, lp := buildF07LabFixture(t, f07Options{withPriorGreetd: true, startSDDM: true})
		lp.failOpID = "start-sddm"
		_, err := Run(ctx, cfg)
		if !errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("expected ErrTransactionAborted on greetd replacement failure, got %v", err)
		}
		assertServiceEnabledState(t, "greetd.service", "enabled")
		assertServiceActiveState(t, "greetd.service", "active")
		assertServiceEnabledState(t, "sddm.service", "disabled")
		assertServiceActiveState(t, "sddm.service", "inactive")

	case "greetd-install":
		cfg, _, _ := buildF07LabFixture(t, f07Options{withPriorGreetd: true, startSDDM: true})
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("greetd approved replacement failed: %v", err)
		}
		m, err := manifest.Load(res.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if m.PreviousDMState.ServiceName != "greetd.service" || m.PreviousDMState.Enabled != "yes" || m.PreviousDMState.Active != "yes" {
			t.Fatalf("unexpected previous DM state: %+v", m.PreviousDMState)
		}
		assertServiceEnabledState(t, "sddm.service", "enabled")
		assertServiceActiveState(t, "sddm.service", "active")
		assertServiceEnabledState(t, "greetd.service", "disabled")
		assertServiceActiveState(t, "greetd.service", "inactive")

	case "greetd-uninstall":
		_, _, lp := buildF07LabFixture(t, f07Options{withPriorGreetd: true})
		if _, err := Uninstall(ctx, UninstallConfig{
			StateRoot:                systemStateRoot,
			Platform:                 lp,
			RemoveSharedDependencies: true,
		}); err != nil {
			t.Fatalf("greetd uninstall failed: %v", err)
		}
		assertServiceEnabledState(t, "greetd.service", "enabled")
		assertServiceActiveState(t, "greetd.service", "active")
		assertServiceEnabledState(t, "sddm.service", "disabled")
		assertServiceActiveState(t, "sddm.service", "inactive")

	// --- Scenario 4: Partial prior installation ---
	case "partial-install":
		cfg, _, _ := buildF07LabFixture(t, f07Options{
			startSDDM:        true,
			preinstalledPkgs: []string{"qt5-translations", "qt5-base"},
		})
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("partial prior install failed: %v", err)
		}
		if res.Mode != "fresh_install" {
			t.Fatalf("expected fresh_install without prior manifest, got %q", res.Mode)
		}
		m, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		var sawQt5BaseExisting bool
		for _, bp := range m.RecoveryBaseline.Packages {
			if bp.PackageReference == "qt5-base" && bp.ExistedBefore {
				sawQt5BaseExisting = true
			}
		}
		if !sawQt5BaseExisting {
			t.Fatalf("expected qt5-base recorded as ExistedBefore in recovery_baseline: %+v", m.RecoveryBaseline.Packages)
		}

	case "partial-repair":
		cfg, _, _ := buildF07LabFixture(t, f07Options{startSDDM: true})
		beforeM, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatalf("missing manifest before repair: %v", err)
		}
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("partial repair failed: %v", err)
		}
		if res.Mode != "repair" {
			t.Fatalf("expected repair, got %q", res.Mode)
		}
		afterM, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(beforeM.RecoveryBaseline, afterM.RecoveryBaseline) {
			t.Fatalf("repair mutated original recovery_baseline")
		}

	case "partial-uninstall":
		_, _, lp := buildF07LabFixture(t, f07Options{})
		if _, err := Uninstall(ctx, UninstallConfig{
			StateRoot:                systemStateRoot,
			Platform:                 lp,
			RemoveSharedDependencies: true,
		}); err != nil {
			t.Fatalf("partial uninstall failed: %v", err)
		}

	// --- Scenario 5: Interrupted installation (SIGKILL + console recovery) ---
	case "interrupt-sigkill-stock", "interrupt-sigkill-nodm":
		noDM := mode == "interrupt-sigkill-nodm"
		cfg, ad, _ := buildF07LabFixture(t, f07Options{noDM: noDM, stockEnabled: !noDM, startSDDM: true})
		ad.beforeVerify = func() {
			fmt.Println("F07_READY")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
		_, _ = Run(ctx, cfg)
		t.Fatal("expected SIGKILL before Run returned")

	case "interrupt-second-refused":
		cfg, _, _ := buildF07LabFixture(t, f07Options{startSDDM: true})
		_, err := Run(ctx, cfg)
		if err == nil {
			t.Fatal("expected second install to be refused while unresolved journal exists")
		}

	case "interrupt-recover":
		_, _, lp := buildF07LabFixture(t, f07Options{})
		if err := RecoverPending(ctx, systemStateRoot, nil, lp); err != nil {
			t.Fatalf("RecoverPending failed: %v", err)
		}
		if err := transaction.CheckNoUnresolved(systemStateRoot + "/transactions"); err != nil {
			t.Fatalf("journal still unresolved after RecoverPending: %v", err)
		}
		if _, err := os.Stat(systemStateRoot + "/manifest.json"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest should not exist after interrupted install rollback: %v", err)
		}

	default:
		t.Fatalf("unknown F07_CASE=%q", mode)
	}
}
