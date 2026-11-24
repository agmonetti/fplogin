package platformclient

import (
	platformv1 "fplogin/internal/protocol/platform/v1"
	"strings"
	"testing"
)

func TestPreparedReferenceIdentity(t *testing.T) {
	request := []platformv1.ArtifactReference{{ArtifactID: "candidate", MediaType: "package", SHA256: strings.Repeat("a", 64), Size: 1}, {ArtifactID: "stock", MediaType: "package", SHA256: strings.Repeat("a", 64), Size: 1}}
	item := `{"artifact_id":"stock","media_type":"package","sha256":"` + request[0].SHA256 + `","size":1,"provider_reference":"local","operation_parameters":{}}`
	good := `{"references":[` + item + `,` + strings.Replace(item, "stock", "candidate", 1) + `]}`
	if err := checkPreparedReferences(request, []byte(good)); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{`{"references":[]}`, strings.Replace(good, "candidate", "stock", 1), strings.Replace(good, "stock", "other", 1), strings.Replace(good, request[0].SHA256, strings.Repeat("b", 64), 1), strings.Replace(good, `"size":1`, `"size":2`, 1), strings.Replace(good, "package", "other", 1)} {
		if checkPreparedReferences(request, []byte(bad)) == nil {
			t.Errorf("accepted %s", bad)
		}
	}
}
