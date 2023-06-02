//go:build v3
// +build v3

package provider

import (
	authlete "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func createSupportedAttachmentsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.StringInSlice([]string{
				string(authlete.ATTACHMENTTYPE_EMBEDDED),
				string(authlete.ATTACHMENTTYPE_EXTERNAL),
			}, false),
		},
	}
}

func mapSupportedAttachmentsToDTO(entry []interface{}) []authlete.AttachmentType {
	var entries = make([]authlete.AttachmentType, 0)

	if entry != nil {
		for _, v := range entry {
			newPair, _ := authlete.NewAttachmentTypeFromValue(v.(string))
			entries = append(entries, *newPair)
		}
	}
	return entries
}

func mapSupportedAttachmentsFromDTO(supportedAttachments []authlete.AttachmentType) []interface{} {

	if supportedAttachments != nil {
		entries := make([]interface{}, len(supportedAttachments), len(supportedAttachments))

		for i, v := range supportedAttachments {
			newEntry := v.Ptr()
			entries[i] = string(*newEntry)
		}
		return entries
	}
	return make([]interface{}, 0)
}
