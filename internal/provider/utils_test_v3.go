//go:build v3
// +build v3

package provider

import (
	"fmt"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"os"
	"strings"
)

func testedAuthleteVersionNotBigger(requiredVersion string) bool {
	authleteVersion := os.Getenv("TC_ACC_AUTHLETE_VERSION")
	if authleteVersion == "" {
		authleteVersion = "2.2"
	}
	return strings.Compare(authleteVersion, requiredVersion) < 0

}

func CheckOutputPresent(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		ms := s.RootModule()
		rs, ok := ms.Outputs[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if rs.Value == nil {
			return fmt.Errorf(
				"Output '%s': expected to have a value, got %#v",
				name,
				rs)
		}

		return nil
	}
}
