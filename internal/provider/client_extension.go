package provider

import (
	authlete "github.com/authlete/openapi-for-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createClientTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.CLIENTTYPE_PUBLIC),
			string(authlete.CLIENTTYPE_CONFIDENTIAL),
		}, false),
	}
}

func createSubjectTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Required: false,
		Optional: true,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			"PUBLIC",
			"PAIRWISE",
		}, false),
	}
}

func mapSubjectTypeToDto(v interface{}) authlete.SubjectType {
	return authlete.SubjectType(v.(string))
}

func createApplicationTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete.APPLICATIONTYPE_WEB),
			string(authlete.APPLICATIONTYPE_NATIVE),
		}, false),
	}
}

func mapApplicationTypeToDto(v interface{}) authlete.ApplicationType {
	return authlete.ApplicationType(v.(string))
}
