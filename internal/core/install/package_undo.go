package install

import (
	"encoding/json"
	"fmt"
	"fplogin/internal/protocol"
)

// Both halves come from the frozen plan, not from a provider receipt. In
// particular undoing a replacement must not describe removing restored stock
// as the way to get the candidate back.
func approvedPackageUndo(op protocol.Operation) (protocol.Operation, error) {
	var u protocol.Operation
	if err := op.Validate(); err != nil {
		return u, err
	}
	c, err := protocol.DecodePackageCompensation(op.Kind, op.Compensation)
	if err != nil {
		return u, err
	}
	u = protocol.Operation{OperationID: op.OperationID + "-rollback", Dependencies: []string{}, Preconditions: []json.RawMessage{}, ExpectedBefore: op.ExpectedAfter, ExpectedAfter: op.ExpectedBefore}
	var original protocol.PackageArtifactParameters
	if err := json.Unmarshal(op.Parameters, &original); err != nil {
		return u, err
	}
	if c.Kind == "remove_package" {
		if original.PackageReference != c.PackageReference {
			return u, fmt.Errorf("undo removes a different package")
		}
		u.Kind = protocol.RemoveOwnedPackage
		u.Parameters, _ = json.Marshal(map[string]string{"package_reference": c.PackageReference})
	} else {
		u.Kind = protocol.InstallPackageArtifact
		u.Parameters, _ = json.Marshal(c.PackageArtifactParameters)
		if op.Kind == protocol.InstallPackageArtifact && original.PackageReference != c.PackageReference {
			// Replacing a package with another package: the restored package transitions from absent to installed.
			u.ExpectedBefore = protocol.Object{"installed": json.RawMessage(`false`)}
			u.ExpectedAfter = protocol.Object{"installed": json.RawMessage(`true`)}
		}
	}
	switch op.Kind {
	case protocol.InstallPackageArtifact:
		u.Compensation, _ = json.Marshal(protocol.PackageCompensation{Kind: "install_package", PackageArtifactParameters: original})
	case protocol.RemoveOwnedPackage:
		if original.PackageReference != c.PackageReference {
			return u, fmt.Errorf("undo restores a different package")
		}
		u.Compensation, _ = json.Marshal(map[string]string{"kind": "remove_package", "package_reference": original.PackageReference})
	default:
		return u, fmt.Errorf("not a package operation")
	}
	return u, u.Validate()
}
