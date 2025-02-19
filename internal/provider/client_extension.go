package provider

import (
	authlete3 "github.com/authlete/openapi-for-go/v3"
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
			string(authlete3.CLIENTTYPE_PUBLIC),
			string(authlete3.CLIENTTYPE_CONFIDENTIAL),
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

func createApplicationTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(authlete3.APPLICATIONTYPE_WEB),
			string(authlete3.APPLICATIONTYPE_NATIVE),
		}, false),
	}
}
