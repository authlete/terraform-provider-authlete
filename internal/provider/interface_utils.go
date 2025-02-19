package provider

import (
	"encoding/json"
	"log"

	idp "github.com/authlete/idp-api"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type ClientWrapper struct {
	v3  *authlete3.APIClient
	idp *idp.APIClient
}

func NewAPIClient(cfg interface{}) ClientWrapper {

	cnf := cfg.(authlete3.Configuration)
	client := authlete3.NewAPIClient(&cnf)
	return ClientWrapper{v3: client}

}

type stringTypes interface {
	authlete3.GrantType | authlete3.ResponseType |
		authlete3.ServiceProfile | authlete3.ClaimType |
		authlete3.Display | authlete3.ClientAuthenticationMethod |
		authlete3.DeliveryMode | authlete3.AttachmentType |
		authlete3.ClientRegistrationType | string | authlete3.JwsAlg |
		authlete3.JweAlg | authlete3.ApplicationType |
		authlete3.SubjectType | authlete3.JweEnc |
		authlete3.UserCodeCharset | authlete3.ClientAuthMethod
}

type structList interface {
	authlete3.Pair | authlete3.Scope | idp.Pair
}

func mapSetToDTO[K stringTypes](vals *schema.Set) []K {
	values := make([]K, vals.Len())
	for i, v := range vals.List() {
		values[i] = K(v.(string))
	}

	return values
}

func mapListToDTO[K stringTypes](vals []interface{}) []K {

	values := make([]K, len(vals))

	for i, v := range vals {
		values[i] = K(v.(string))
	}
	return values
}

func mapFromDTO[K stringTypes](vals []K) []interface{} {
	var result = make([]interface{}, len(vals))

	if vals != nil {
		for i, v := range vals {
			var str string = string(v)
			result[i] = str
		}
	}
	return result
}

func mapInterfaceListToStructList[K structList](vals []interface{}) []K {
	targetStruct := []K{}
	temporaryVariable, _ := json.Marshal(vals)
	err := json.Unmarshal(temporaryVariable, &targetStruct)
	if err != nil {
		log.Fatalf("error unmarshaling")
	}
	return targetStruct
}

func mapInterfaceToType[K stringTypes](val interface{}) K {
	return K(val.(string))
}

func mapTypeToString[K stringTypes](val K) string {
	return string(val)
}
