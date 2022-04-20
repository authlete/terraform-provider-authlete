package provider

import (
	"github.com/authlete/authlete-go/types"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createClientExtensionSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeMap,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{},
		},
	}
}

func createClientTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(types.ClientType_PUBLIC),
			string(types.ClientType_CONFIDENTIAL),
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
			string(types.SubjectType_PUBLIC),
			string(types.SubjectType_PAIRWISE),
		}, false),
	}
}

func mapSubjectTypeToDto(v interface{}) types.SubjectType {
	return types.SubjectType(v.(string))
}

func createApplicationTypeSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeString,
		Optional: true,
		Required: false,
		Computed: true,
		ValidateFunc: validation.StringInSlice([]string{
			string(types.ApplicationType_WEB),
			string(types.ApplicationType_NATIVE),
		}, false),
	}
}

func mapApplicationTypeToDto(v interface{}) types.ApplicationType {
	return types.ApplicationType(v.(string))
}
