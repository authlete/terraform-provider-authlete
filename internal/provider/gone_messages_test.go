package provider

import (
	"strings"
	"testing"
)

func TestMissingLocationMessageExplainsSafeRecovery(t *testing.T) {
	summary, detail := noRecordMessage("client", "42")
	if !strings.Contains(summary, "client 42") {
		t.Fatalf("diagnostic does not identify the affected client: %s", summary)
	}
	for _, want := range []string{"server_url", "idp_host", "organization_id", "api_server_id", "terraform apply -refresh-only", "terraform state rm"} {
		if !strings.Contains(detail, want) {
			t.Errorf("recovery diagnostic omits %q", want)
		}
	}
}
func TestExistingServiceMessageNamesItsLocation(t *testing.T) {
	summary, detail := serviceStillThereMessage("42", Location{Host: "api.example", IdpHost: "idp.example", Org: 11, API: 53285})
	if !strings.Contains(summary, "still exists") {
		t.Errorf("summary hides refusal reason: %s", summary)
	}
	for _, want := range []string{"42", "api.example", "idp.example", "organization_id", "api_server_id", "idp_host"} {
		if !strings.Contains(detail, want) {
			t.Errorf("existing-service diagnostic omits %q", want)
		}
	}
}
