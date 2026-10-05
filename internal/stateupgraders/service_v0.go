// Generated once by Speakeasy as a no-op stub, then filled in by hand. The
// generator marks this path untracked and only writes it when absent, so this
// body survives `speakeasy run`. See upgrade.go for why the migration works the
// way it does.
package stateupgraders

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// ServiceStateUpgraderV0 migrates authlete_service state written by v1.3.x.
//
// v1.3.17 stored the service's API key in SDKv2's implicit `id` as a string
// (service.go: d.SetId(strconv.FormatInt(*apiKey, 10))). This provider models
// it as the Int64 attribute `api_key`, and has no `id` attribute at all.
func ServiceStateUpgraderV0(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
	upgrade(ctx, "service", []rename{
		{
			from:      "id",
			to:        "api_key",
			toNumber:  true,
			mustBeSet: true,
			ifNotSetSay: "This state was written by provider version 1.3.x, which stored the " +
				"service's API key in `id`. That value is missing, so there is nothing to " +
				"identify the service with.\n\n" +
				"Recover it by removing the resource from state and importing it again:\n\n" +
				"  terraform state rm authlete_service.<name>\n" +
				"  terraform import authlete_service.<name> <service api key>\n\n" +
				"The API key is shown in the Authlete console. Importing preserves the " +
				"service and everything under it; nothing is recreated.",
		},
	}, req, resp)
}
