package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePackages(t *testing.T) {
	inventory := "Name : pacman\nVersion : 7.1-1\nProvides : None\n\nName : gdm\nVersion : 49.0-1\nProvides : display-manager\n"
	packages, err := parsePackages(inventory, []string{"fprintd"})
	if err != nil || len(packages) != 2 || packages[0].PackageReference != "fprintd" || packages[0].Installed != "no" || packages[1].PackageReference != "gdm" || packages[1].Installed != "yes" {
		t.Fatalf("packages = %+v, error = %v", packages, err)
	}
	for _, malformed := range []string{"", "Name : pacman\nProvides : None", inventory + "\n" + inventory} {
		if _, err := parsePackages(malformed, nil); err == nil {
			t.Fatal("accepted incomplete or contradictory package inventory")
		}
	}
}

func TestServiceInventory(t *testing.T) {
	for _, tc := range []struct {
		name, files, loaded, id, loadState, active, enabled, graphical, dropIn, wantedBy, want string
		dependencyDir, partialReverse                                                          bool
	}{
		{name: "no display manager", files: "dbus.service static -\n", loaded: "dbus.service loaded active running D-Bus\n", graphical: "Wants=display-manager.service\nRequires=multi-user.target\n"},
		{name: "no display manager with graphical not-found stub", files: "dbus.service static -\n", loaded: "dbus.service loaded active running D-Bus\ndisplay-manager.service not-found inactive dead display-manager.service\n", id: "display-manager.service", loadState: "not-found", active: "inactive", enabled: "", graphical: "Wants=display-manager.service\nRequires=multi-user.target\n", wantedBy: "graphical.target"},
		{name: "broken display-manager alias to custom unit", files: "dbus.service static -\n", loaded: "display-manager.service not-found inactive dead custom-dm.service\n", id: "custom-dm.service", loadState: "not-found", active: "inactive", enabled: "", graphical: "Wants=display-manager.service\nRequires=multi-user.target\n", wantedBy: "graphical.target", want: "error"},
		{name: "stock", files: "sddm.service enabled disabled\ndisplay-manager.service alias -\n", id: "sddm.service", active: "active", enabled: "enabled", want: "yes/yes"},
		{name: "enabled inactive", files: "gdm.service enabled disabled\n", id: "gdm.service", active: "inactive", enabled: "enabled", want: "no/yes"},
		{name: "active disabled", loaded: "lightdm.service loaded active running LightDM\n", id: "lightdm.service", active: "active", enabled: "disabled", want: "yes/no"},
		{name: "unknown alias", files: "display-manager.service alias -\n", id: "custom.service", active: "active", enabled: "enabled", want: "error"},
		{name: "runtime enabled", files: "gdm.service enabled-runtime -\n", id: "gdm.service", active: "active", enabled: "enabled-runtime", want: "error"},
		{name: "canonical stock dependency", files: "sddm.service enabled disabled\ndisplay-manager.service alias -\n", id: "sddm.service", active: "inactive", enabled: "enabled", graphical: "Wants=sddm.service\nRequires=multi-user.target\n", wantedBy: "graphical.target", want: "no/yes"},
		{name: "multi-user target also wants enabled alias target", files: "greetd.service enabled disabled\ndisplay-manager.service alias -\n", id: "greetd.service", active: "inactive", enabled: "enabled", graphical: "Wants=greetd.service\nRequires=multi-user.target\n", wantedBy: "graphical.target multi-user.target", want: "error"},
		{name: "incomplete reverse dependency report", files: "greetd.service disabled disabled\n", id: "greetd.service", active: "inactive", enabled: "disabled", partialReverse: true, want: "error"},
		{name: "duplicate explicit want of enabled alias target", files: "display-manager.service alias -\n", id: "greetd.service", active: "inactive", enabled: "enabled", graphical: "Wants=greetd.service\nRequires=multi-user.target\n", dropIn: "/etc/systemd/system/graphical.target.d/dm.conf", want: "error"},
		{name: "dependency directory also pulls in enabled alias target", files: "display-manager.service alias -\n", id: "greetd.service", active: "inactive", enabled: "enabled", graphical: "Wants=greetd.service\nRequires=multi-user.target\n", dependencyDir: true, want: "error"},
		{name: "graphical binds to DM", graphical: "Wants=\nRequires=multi-user.target\nBindsTo=greetd.service\nUpholds=\n", want: "error"},
		{name: "graphical upholds DM", graphical: "Wants=\nRequires=multi-user.target\nBindsTo=\nUpholds=greetd.service\n", want: "error"},
		{name: "graphical wants disabled DM", files: "greetd.service disabled disabled\n", id: "greetd.service", active: "inactive", enabled: "disabled", graphical: "Wants=greetd.service\nRequires=multi-user.target\n", want: "error"},
		{name: "graphical requires static DM", files: "greetd.service static -\n", id: "greetd.service", active: "inactive", enabled: "static", graphical: "Wants=\nRequires=greetd.service multi-user.target\n", want: "error"},
		{name: "graphical dependency not in inventory", graphical: "Wants=ly@tty2.service\nRequires=multi-user.target\n", want: "error"},
		{name: "partial graphical report", graphical: "Requires=multi-user.target\n", want: "error"},
		{name: "bus failure", loaded: "error", want: "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unitPath := t.TempDir()
			if tc.dependencyDir {
				dir := filepath.Join(unitPath, "graphical.target.wants")
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("../greetd.service", filepath.Join(dir, "greetd.service")); err != nil {
					t.Fatal(err)
				}
			}
			query := func(_ context.Context, path string, args ...string) (string, error) {
				if path != "/usr/bin/systemctl" {
					t.Fatalf("unexpected command: %s", path)
				}
				text := strings.Join(args, " ")
				switch {
				case strings.Contains(text, "list-unit-files"):
					return tc.files, nil
				case strings.Contains(text, "list-units"):
					if tc.loaded == "error" {
						return "", errors.New("system bus unavailable")
					}
					return tc.loaded, nil
				case strings.HasSuffix(text, " --property=UnitPath"):
					return "UnitPath=" + unitPath + "\n", nil
				case strings.HasSuffix(text, " graphical.target"):
					deps := tc.graphical
					if deps == "" {
						deps = "Wants=\nRequires=multi-user.target\n"
					}
					if !strings.Contains(deps, "BindsTo=") {
						deps += "BindsTo=\nUpholds=\n"
					}
					return deps + "LoadState=loaded\nNeedDaemonReload=no\nFragmentPath=/usr/lib/systemd/system/graphical.target\nDropInPaths=" + tc.dropIn + "\n", nil
				case strings.Contains(text, " show "):
					ls := tc.loadState
					if ls == "" {
						ls = "loaded"
					}
					props := "Id=" + tc.id + "\nLoadState=" + ls + "\nActiveState=" + tc.active + "\nUnitFileState=" + tc.enabled + "\nWantedBy=" + tc.wantedBy + "\n"
					if !tc.partialReverse {
						props += "RequiredBy=\nBoundBy=\nUpheldBy=\n"
					}
					return props, nil
				default:
					t.Fatalf("unexpected query %v", args)
					return "", nil
				}
			}
			s, err := queryServices(context.Background(), nil, query)
			switch tc.want {
			case "error":
				if err == nil {
					t.Fatalf("expected unknown state, got %+v", s)
				}
			case "":
				if err != nil || len(s) != 0 {
					t.Fatalf("want known absence, got %+v %v", s, err)
				}
			default:
				if err != nil || len(s) != 1 || s[0].Active+"/"+s[0].Enabled != tc.want {
					t.Fatalf("services = %+v, error = %v", s, err)
				}
			}
		})
	}
}
