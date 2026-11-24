package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"fplogin/internal/protocol"
	adapterv1 "fplogin/internal/protocol/adapter/v1"
	platformv1 "fplogin/internal/protocol/platform/v1"
)

func testSHA(s string) string {
	return calcSHA256([]byte(s))
}

func baseTestArtifacts() []artifactMeta {
	return []artifactMeta{
		{Package: "sddm-fplogin", Version: "0.21.0-3.1", SHA256: testSHA("sddm-fplogin"), Size: 100, MediaType: "application/zstd"},
		{Package: "sddm", Version: "0.21.0-7", SHA256: testSHA("sddm"), Size: 90, MediaType: "application/zstd"},
		{Package: "qt5-base", Version: "5.15.19-1", SHA256: testSHA("qt5-base"), Size: 80, MediaType: "application/zstd"},
		{Package: "qt5-translations", Version: "5.15.19-1", SHA256: testSHA("qt5-translations"), Size: 70, MediaType: "application/zstd"},
	}
}

func makeLiveReq(t *testing.T, facts adapterv1.PreflightFacts, artifacts []artifactMeta, installed map[string]string, activate bool) adapterv1.Request {
	t.Helper()
	invRaw, _ := json.Marshal(facts)
	artRaw, _ := json.Marshal(artifacts)
	instRaw, _ := json.Marshal(installed)
	actRaw, _ := json.Marshal(activate)
	return adapterv1.Request{
		ProtocolVersion: protocol.Version{Major: 1, Minor: 0},
		RequestID:       "00000000-0000-0000-0000-000000000001",
		Operation:       "PlanInstall",
		CoreVersion:     "0.2.0",
		Context: protocol.HostContext{
			Root:         "/",
			Architecture: "x86_64",
			DryRun:       false,
			Elevated:     false,
			Platform: protocol.Object{
				"distribution":       json.RawMessage(`"arch"`),
				"inventory":          invRaw,
				"artifacts":          artRaw,
				"installed_packages": instRaw,
				"activate":           actRaw,
			},
		},
	}
}

func TestDetectSDDMLive_PatchedCompatible(t *testing.T) {
	facts := adapterv1.PreflightFacts{
		Packages: []platformv1.PackageCandidate{
			{PackageReference: "sddm-fplogin", Installed: "yes", Version: json.RawMessage(`"0.21.0-3.1"`)},
			{PackageReference: "fprintd", Installed: "yes", Version: json.RawMessage(`"1.94.5-1"`)},
		},
		Services: []platformv1.ServiceCandidate{
			{ServiceReference: "sddm.service", Enabled: "yes", Active: "no", Configurable: "yes"},
		},
	}
	if dry := detectSDDM(facts); dry.Compatibility != "incompatible" {
		t.Fatalf("dry-run should keep patched incompatible, got %s", dry.Compatibility)
	}
	if live := detectSDDMLive(facts); live.Compatibility != "compatible" {
		t.Fatalf("live detect should allow reinstall/repair of patched 0.21.0, got %s", live.Compatibility)
	}
}

func TestPlanExecutableInstall_Scenarios(t *testing.T) {
	if _, err := os.Lstat("/etc/sddm.conf.d"); err != nil {
		t.Skip("/etc/sddm.conf.d absent on test host")
	}

	t.Run("stock sddm replacement with deterministic digest", func(t *testing.T) {
		facts := adapterv1.PreflightFacts{
			Packages: []platformv1.PackageCandidate{
				{PackageReference: "sddm", Installed: "yes", Version: json.RawMessage(`"0.21.0-7"`)},
				{PackageReference: "fprintd", Installed: "yes", Version: json.RawMessage(`"1.94.5-1"`)},
			},
			Services: []platformv1.ServiceCandidate{
				{ServiceReference: "sddm.service", Enabled: "yes", Active: "no", Configurable: "yes"},
			},
		}
		target := detectSDDMLive(facts)
		req := makeLiveReq(t, facts, baseTestArtifacts(), map[string]string{"sddm": "0.21.0-7"}, false)
		p1, err := planExecutableInstall(req, facts, target, adapterv1.PlanInstallPayload{Mode: "fresh_install"})
		if err != nil {
			t.Fatalf("planExecutableInstall: %v", err)
		}
		p2, err := planExecutableInstall(req, facts, target, adapterv1.PlanInstallPayload{Mode: "fresh_install"})
		if err != nil {
			t.Fatalf("second planExecutableInstall: %v", err)
		}
		b1, _ := json.Marshal(p1)
		b2, _ := json.Marshal(p2)
		if string(b1) != string(b2) {
			t.Fatalf("plan is not deterministic across identical runs")
		}
		// Verify dependency ordering: qt5-translations before qt5-base before sddm-fplogin before write-theme before enable-sddm.
		wantOrder := []string{"pkg-qt5-translations", "pkg-qt5-base", "pkg-sddm-fplogin", "write-theme", "enable-sddm"}
		if len(p1.Operations) != len(wantOrder) {
			t.Fatalf("got %d ops, want %d", len(p1.Operations), len(wantOrder))
		}
		for i, want := range wantOrder {
			if p1.Operations[i].OperationID != want {
				t.Fatalf("op[%d] = %q, want %q", i, p1.Operations[i].OperationID, want)
			}
		}
		if !strings.Contains(string(p1.Operations[2].Compensation), `"kind":"install_package"`) {
			t.Fatalf("expected stock sddm rollback compensation, got %s", p1.Operations[2].Compensation)
		}
	})

	t.Run("conflicting active greetd with activate", func(t *testing.T) {
		facts := adapterv1.PreflightFacts{
			Packages: []platformv1.PackageCandidate{
				{PackageReference: "fprintd", Installed: "yes", Version: json.RawMessage(`"1.94.5-1"`)},
			},
			Services: []platformv1.ServiceCandidate{
				{ServiceReference: "greetd.service", Enabled: "yes", Active: "yes", Configurable: "yes"},
			},
		}
		target := detectSDDMLive(facts)
		req := makeLiveReq(t, facts, baseTestArtifacts(), map[string]string{}, true)
		plan, err := planExecutableInstall(req, facts, target, adapterv1.PlanInstallPayload{Mode: "fresh_install"})
		if err != nil {
			t.Fatalf("planExecutableInstall: %v", err)
		}
		if len(plan.Approvals) != 1 || plan.Approvals[0].ID != "replace-dm-greetd.service" {
			t.Fatalf("expected conflicting DM approval, got %+v", plan.Approvals)
		}
		// Stock sddm must NOT be included when no stock sddm is installed.
		for _, ref := range plan.ArtifactReferences {
			if ref.ArtifactID == "sddm" {
				t.Fatalf("unexpected stock sddm reference in no-DM install")
			}
		}
		wantTail := []string{"write-theme", "stop-greetd.service", "disable-greetd.service", "enable-sddm", "start-sddm"}
		gotTail := make([]string, 0, len(wantTail))
		for _, op := range plan.Operations[len(plan.Operations)-len(wantTail):] {
			gotTail = append(gotTail, op.OperationID)
		}
		if strings.Join(gotTail, ",") != strings.Join(wantTail, ",") {
			t.Fatalf("service op tail = %v, want %v", gotTail, wantTail)
		}
	})

	t.Run("missing stock rollback archive refused", func(t *testing.T) {
		facts := adapterv1.PreflightFacts{
			Packages: []platformv1.PackageCandidate{
				{PackageReference: "sddm", Installed: "yes", Version: json.RawMessage(`"0.21.0-7"`)},
				{PackageReference: "fprintd", Installed: "yes", Version: json.RawMessage(`"1.94.5-1"`)},
			},
			Services: []platformv1.ServiceCandidate{
				{ServiceReference: "sddm.service", Enabled: "yes", Active: "no", Configurable: "yes"},
			},
		}
		target := detectSDDMLive(facts)
		arts := []artifactMeta{baseTestArtifacts()[0]} // sddm-fplogin only, no stock sddm
		req := makeLiveReq(t, facts, arts, map[string]string{"sddm": "0.21.0-7"}, false)
		if _, err := planExecutableInstall(req, facts, target, adapterv1.PlanInstallPayload{Mode: "fresh_install"}); err == nil {
			t.Fatal("expected refusal when stock sddm rollback archive is missing")
		}
	})
}
