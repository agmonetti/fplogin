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
	"slices"
	"strings"
	"testing"

	"fplogin/internal/core/manifest"
	"fplogin/internal/core/transaction"
	"fplogin/internal/protocol"
)

func buildF06LabFixture(t *testing.T, withPriorLightDM bool) (Config, *fakeAdapterInvoker, labPlatform) {
	t.Helper()
	cfg, ad, lp := buildLabFixture(t)
	// Mark qt5-* packages as shared dependencies so default uninstall preserves them.
	for i := range ad.plan.ArtifactReferences {
		if strings.HasPrefix(ad.plan.ArtifactReferences[i].ArtifactID, "qt5-") {
			ad.plan.ArtifactReferences[i].Role = "shared_dependency"
		} else if ad.plan.ArtifactReferences[i].ArtifactID == "sddm-fplogin" {
			ad.plan.ArtifactReferences[i].Role = "display_manager_package"
		}
	}
	if withPriorLightDM {
		disablePrior := protocol.Operation{
			OperationID:    "disable-lightdm",
			Kind:           protocol.SetServiceEnabled,
			Dependencies:   []string{},
			Preconditions:  []json.RawMessage{},
			ExpectedBefore: protocol.Object{"enabled": json.RawMessage(`true`)},
			ExpectedAfter:  protocol.Object{"enabled": json.RawMessage(`false`)},
			Parameters:     json.RawMessage(`{"service_reference":"lightdm.service","enabled":false}`),
			Compensation:   json.RawMessage(`{"kind":"set_service_enabled","service_reference":"lightdm.service","enabled":true}`),
		}
		// Insert before enable-sddm (last op).
		last := ad.plan.Operations[len(ad.plan.Operations)-1]
		ad.plan.Operations = append(ad.plan.Operations[:len(ad.plan.Operations)-1], disablePrior, last)
	}
	return cfg, ad, lp
}

func assertServiceEnabledState(t *testing.T, unit, want string) {
	t.Helper()
	out, _ := exec.Command("/usr/bin/systemctl", "is-enabled", unit).CombinedOutput()
	got := strings.TrimSpace(string(out))
	if got != want {
		t.Fatalf("expected %s is-enabled=%q, got %q", unit, want, got)
	}
}

func TestF06LabLifecycle(t *testing.T) {
	mode := os.Getenv("F06_CASE")
	if mode == "" {
		t.Skip("F06_CASE not set")
	}
	ctx := context.Background()

	switch mode {
	case "fresh-install":
		cfg, _, _ := buildF06LabFixture(t, false)
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("fresh install failed: %v", err)
		}
		if res.Mode != "fresh_install" {
			t.Fatalf("expected fresh_install, got %q", res.Mode)
		}
		m, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatalf("manifest not published: %v", err)
		}
		if m.TransactionID != res.TransactionID || m.RecoveryBaseline == nil || len(m.InstalledPackages) != 6 || len(m.InstalledFiles) != 1 {
			t.Fatalf("unexpected manifest: %+v", m)
		}

	case "reinstall":
		cfg, _, _ := buildF06LabFixture(t, false)
		beforeM, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatalf("missing prior manifest: %v", err)
		}
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("reinstall failed: %v", err)
		}
		if res.Mode != "reinstall" {
			t.Fatalf("expected reinstall, got %q", res.Mode)
		}
		afterM, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(beforeM.RecoveryBaseline, afterM.RecoveryBaseline) {
			t.Fatalf("reinstall altered original recovery baseline:\nbefore=%+v\nafter=%+v", beforeM.RecoveryBaseline, afterM.RecoveryBaseline)
		}

	case "repair":
		cfg, _, _ := buildF06LabFixture(t, false)
		beforeM, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatalf("missing prior manifest: %v", err)
		}
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("repair failed: %v", err)
		}
		if res.Mode != "repair" {
			t.Fatalf("expected repair, got %q", res.Mode)
		}
		afterM, err := manifest.Load(cfg.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(beforeM.RecoveryBaseline, afterM.RecoveryBaseline) {
			t.Fatalf("repair altered original recovery baseline")
		}

	case "uninstall-default":
		// No adapter invoker or discoverer is passed to Uninstall.
		_, _, lp := buildF06LabFixture(t, false)
		uRes, err := Uninstall(ctx, UninstallConfig{
			StateRoot: systemStateRoot,
			Platform:  lp,
		})
		if err != nil {
			t.Fatalf("uninstall-default failed: %v", err)
		}
		if len(uRes.KeptSharedPackages) != 5 {
			t.Fatalf("expected 5 shared qt5 packages kept, got %v", uRes.KeptSharedPackages)
		}
		if _, err := os.Stat(systemStateRoot + "/manifest.json"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest still exists after uninstall: %v", err)
		}
		assertServiceEnabledState(t, "sddm.service", "disabled")

	case "uninstall-repeat":
		_, _, lp := buildF06LabFixture(t, false)
		if _, err := Uninstall(ctx, UninstallConfig{
			StateRoot: systemStateRoot,
			Platform:  lp,
		}); !errors.Is(err, manifest.ErrManifestNotFound) {
			t.Fatalf("expected ErrManifestNotFound on repeat uninstall, got %v", err)
		}

	case "uninstall-modified-refuse":
		_, _, lp := buildF06LabFixture(t, false)
		if _, err := Uninstall(ctx, UninstallConfig{
			StateRoot:     systemStateRoot,
			Platform:      lp,
			ModifiedFiles: ModifiedFileRefuse,
		}); !errors.Is(err, manifest.ErrModifiedFiles) {
			t.Fatalf("expected ErrModifiedFiles, got %v", err)
		}
		if _, err := manifest.Load(systemStateRoot + "/manifest.json"); err != nil {
			t.Fatalf("manifest lost after refused uninstall: %v", err)
		}

	case "uninstall-modified-preserve":
		_, _, lp := buildF06LabFixture(t, false)
		uRes, err := Uninstall(ctx, UninstallConfig{
			StateRoot: systemStateRoot,
			Platform:  lp,
		})
		if err != nil {
			t.Fatalf("uninstall-modified-preserve failed: %v", err)
		}
		if !slices.Equal(uRes.PreservedFiles, []string{systemThemeFile}) {
			t.Fatalf("expected %s preserved, got %v", systemThemeFile, uRes.PreservedFiles)
		}
		assertServiceEnabledState(t, "sddm.service", "disabled")

	case "uninstall-remove-shared":
		_, _, lp := buildF06LabFixture(t, false)
		uRes, err := Uninstall(ctx, UninstallConfig{
			StateRoot:                systemStateRoot,
			Platform:                 lp,
			RemoveSharedDependencies: true,
		})
		if err != nil {
			t.Fatalf("uninstall-remove-shared failed: %v", err)
		}
		if len(uRes.KeptSharedPackages) != 0 {
			t.Fatalf("expected 0 kept shared packages, got %v", uRes.KeptSharedPackages)
		}
		assertServiceEnabledState(t, "sddm.service", "disabled")

	case "install-with-prior-lightdm":
		cfg, _, _ := buildF06LabFixture(t, true)
		res, err := Run(ctx, cfg)
		if err != nil {
			t.Fatalf("install with prior lightdm failed: %v", err)
		}
		m, err := manifest.Load(res.ManifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if m.PreviousDMState.ServiceName != "lightdm.service" || m.PreviousDMState.Enabled != "yes" {
			t.Fatalf("unexpected previous DM state: %+v", m.PreviousDMState)
		}
		assertServiceEnabledState(t, "sddm.service", "enabled")
		assertServiceEnabledState(t, "lightdm.service", "disabled")

	case "uninstall-service-fail":
		_, _, lp := buildF06LabFixture(t, true)
		lp.failOpID = "uninstall-svc-restore-0"
		_, err := Uninstall(ctx, UninstallConfig{
			StateRoot: systemStateRoot,
			Platform:  lp,
		})
		if !errors.Is(err, ErrTransactionAborted) {
			t.Fatalf("expected ErrTransactionAborted on service restore failure, got %v", err)
		}
		if _, err := manifest.Load(systemStateRoot + "/manifest.json"); err != nil {
			t.Fatalf("manifest was not kept after failed service restore: %v", err)
		}
		assertServiceEnabledState(t, "sddm.service", "enabled")
		assertServiceEnabledState(t, "lightdm.service", "disabled")
		if err := transaction.CheckNoUnresolved(systemStateRoot + "/transactions"); err != nil {
			t.Fatalf("journal still unresolved after rolled-back uninstall: %v", err)
		}

	case "uninstall-prior-lightdm":
		_, _, lp := buildF06LabFixture(t, true)
		if _, err := Uninstall(ctx, UninstallConfig{
			StateRoot: systemStateRoot,
			Platform:  lp,
		}); err != nil {
			t.Fatalf("uninstall restoring lightdm failed: %v", err)
		}
		assertServiceEnabledState(t, "sddm.service", "disabled")
		assertServiceEnabledState(t, "lightdm.service", "enabled")
		if _, err := os.Stat(systemStateRoot + "/manifest.json"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("manifest still exists: %v", err)
		}

	case "sigkill-after-publish":
		cfg, _, _ := buildF06LabFixture(t, false)
		testAfterManifestPublish = func(string) {
			fmt.Println("F06_READY")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
		defer func() { testAfterManifestPublish = nil }()
		_, err := Run(ctx, cfg)
		t.Fatalf("expected SIGKILL after manifest publish, got %v", err)

	case "sigkill-before-remove":
		_, _, lp := buildF06LabFixture(t, false)
		testBeforeManifestRemove = func(string) {
			fmt.Println("F06_READY")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
		defer func() { testBeforeManifestRemove = nil }()
		_, err := Uninstall(ctx, UninstallConfig{StateRoot: systemStateRoot, Platform: lp})
		t.Fatalf("expected SIGKILL before manifest remove, got %v", err)

	case "sigkill-after-remove":
		_, _, lp := buildF06LabFixture(t, false)
		testAfterManifestRemove = func(string) {
			fmt.Println("F06_READY")
			_, _ = io.Copy(io.Discard, os.Stdin)
		}
		defer func() { testAfterManifestRemove = nil }()
		_, err := Uninstall(ctx, UninstallConfig{StateRoot: systemStateRoot, Platform: lp})
		t.Fatalf("expected SIGKILL after manifest remove, got %v", err)

	case "recover-pending":
		cfg, _, lp := buildF06LabFixture(t, false)
		// Second Run must be refused while journal is unresolved.
		if _, err := Run(ctx, cfg); !errors.Is(err, transaction.ErrUnresolvedTransaction) {
			t.Fatalf("expected ErrUnresolvedTransaction before recovery, got %v", err)
		}
		if err := RecoverPending(ctx, systemStateRoot, nil, lp); err != nil {
			t.Fatalf("RecoverPending failed: %v", err)
		}
		if err := transaction.CheckNoUnresolved(systemStateRoot + "/transactions"); err != nil {
			t.Fatalf("journal still unresolved after RecoverPending: %v", err)
		}

	default:
		t.Fatalf("unknown F06_CASE %q", mode)
	}
}
