// Generated once by Speakeasy as a no-op stub, then filled in by hand. The
// generator marks this path untracked and only writes it when absent, so this
// body survives `speakeasy run`. See upgrade.go for why the migration works the
// way it does.
package stateupgraders

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ClientStateUpgraderV0 migrates authlete_client state written by v1.3.x.
//
// Two identifiers move. The client id was SDKv2's implicit `id`, a string
// (client.go: d.SetId(strconv.FormatInt(newOauthClient.GetClientId(), 10)));
// it is now the Int64 attribute `client_id`. The parent service was
// `service_api_key`, and is now `service_id`.
//
// `service_api_key` was Optional in v1.3.17: left empty, the provider fell back
// to the provider-level `api_key`. That fallback is gone -- `service_id` is
// Required per client -- and the value was never written to state, so it cannot
// be recovered here. Those resources stop with remediation rather than
// producing state whose next refresh calls /api//client/get/<id>.
func ClientStateUpgraderV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	upgrade(ctx, "client", []rename{
		{
			from:      "id",
			to:        "client_id",
			toNumber:  true,
			mustBeSet: true,
			ifNotSetSay: "This state was written by provider version 1.3.x, which stored the " +
				"client id in `id`. That value is missing, so there is nothing to identify " +
				"the client with.\n\n" +
				"Recover it by removing the resource from state and importing it again:\n\n" +
				"  terraform state rm authlete_client.<name>\n" +
				"  terraform import authlete_client.<name> '{\"client_id\": <client id>, \"service_id\": \"<service api key>\"}'\n\n" +
				"The client importer takes a JSON object, not a slash-separated pair. Both " +
				"values are shown in the Authlete console. Importing preserves the client " +
				"and its secret; nothing is recreated.",
		},
		{
			from:      "service_api_key",
			to:        "service_id",
			mustBeSet: true,
			ifNotSetSay: "This client's state does not record which service it belongs to.\n\n" +
				"In provider version 1.3.x, `service_api_key` was optional on the client: " +
				"left unset, the provider used the `api_key` from the provider block, and " +
				"that value was never written to state. This provider has no provider-level " +
				"api_key and requires `service_id` on each client, so the service cannot be " +
				"inferred.\n\n" +
				"Set `service_id` in configuration, then re-adopt this resource:\n\n" +
				"  terraform state rm authlete_client.<name>\n" +
				"  terraform import authlete_client.<name> '{\"client_id\": <client id>, \"service_id\": \"<service api key>\"}'\n\n" +
				"The client importer takes a JSON object, not a slash-separated pair. " +
				"Importing preserves the client and its secret; nothing is recreated.",
		},
	}, req, resp)
}
