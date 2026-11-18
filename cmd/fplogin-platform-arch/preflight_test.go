package main

import (
	"context"
	"errors"
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
		name, files, loaded, id, active, enabled, want string
	}{
		{name: "no display manager", files: "dbus.service static -\n", loaded: "dbus.service loaded active running D-Bus\n"},
		{name: "stock", files: "sddm.service enabled disabled\ndisplay-manager.service alias -\n", id: "sddm.service", active: "active", enabled: "enabled", want: "yes/yes"},
		{name: "enabled inactive", files: "gdm.service enabled disabled\n", id: "gdm.service", active: "inactive", enabled: "enabled", want: "no/yes"},
		{name: "active disabled", loaded: "lightdm.service loaded active running LightDM\n", id: "lightdm.service", active: "active", enabled: "disabled", want: "yes/no"},
		{name: "unknown alias", files: "display-manager.service alias -\n", id: "custom.service", active: "active", enabled: "enabled", want: "error"},
		{name: "runtime enabled", files: "gdm.service enabled-runtime -\n", id: "gdm.service", active: "active", enabled: "enabled-runtime", want: "error"},
		{name: "bus failure", loaded: "error", want: "error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
				case strings.HasSuffix(text, " graphical.target"):
					return "Wants=display-manager.service\nRequires=multi-user.target\n", nil
				case strings.Contains(text, " show "):
					return "Id=" + tc.id + "\nLoadState=loaded\nActiveState=" + tc.active + "\nUnitFileState=" + tc.enabled + "\n", nil
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
