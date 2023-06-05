package provider

import (
	"encoding/json"
	"log"

	authlete "github.com/authlete/openapi-for-go/v2"
	authlete3 "github.com/authlete/openapi-for-go/v3"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// type APIClient authlete.APIClient
type Configuration *authlete.Configuration

type Pair interface {
	// GetKey returns the Key field value if set, zero value otherwise.
	GetKey() string

	// GetKeyOk returns a tuple with the Key field value if set, nil otherwise
	// and a boolean to check if the value has been set.
	GetKeyOk() (*string, bool)

	HasKey() bool

	SetKey(v string)

	GetValue() string

	GetValueOk() (*string, bool)

	HasValue() bool

	SetValue(v string)

	MarshalJSON() ([]byte, error)

	ToMap() (map[string]interface{}, error)
}
type ClientWrapper struct {
	v2 *authlete.APIClient
	v3 *authlete3.APIClient
}

type TrustAnchor interface {
	authlete.TrustAnchor | authlete3.TrustAnchor | any
}

func NewAPIClient(cfg interface{}) ClientWrapper {
	if v3 {
		cnf := cfg.(authlete3.Configuration)
		client := authlete3.NewAPIClient(&cnf)
		return ClientWrapper{v3: client}
	} else {
		cnf := cfg.(authlete.Configuration)
		v2Client := authlete.NewAPIClient(&cnf)
		return ClientWrapper{v2: v2Client}
	}

}

// ConvertArray converts an array of one type to an array of another type
type V3 interface {
	authlete.GrantType | authlete3.GrantType | authlete3.ResponseType | authlete.ResponseType |
		authlete3.ServiceProfile | authlete.ServiceProfile | authlete3.ClaimType | authlete.ClaimType |
		authlete3.Display | authlete.Display | authlete3.ClientAuthenticationMethod | authlete.ClientAuthenticationMethod |
		authlete3.DeliveryMode | authlete.DeliveryMode | authlete3.AttachmentType | authlete.AttachmentType |
		authlete3.ClientRegistrationType | authlete.ClientRegistrationType | string | authlete3.JwsAlg | authlete.JwsAlg |
		authlete.JweAlg | authlete3.JweAlg
}

type structList interface {
	authlete.Pair | authlete3.Pair | authlete3.Scope | authlete.Scope
}

func mapSetToDTO[K V3](vals *schema.Set) []K {
	values := make([]K, vals.Len())
	for i, v := range vals.List() {
		values[i] = K(v.(string))
	}

	return values
}

func mapListToDTO[K V3](vals []interface{}) []K {

	values := make([]K, len(vals))

	for i, v := range vals {
		values[i] = K(v.(string))
	}
	return values
}

func mapFromDTO[K V3](vals []K) []interface{} {
	var result = make([]interface{}, len(vals))

	if vals != nil {
		for i, v := range vals {
			var str string = string(v)
			result[i] = str
		}
	}
	return result
}

func mapInterfaceListToStruct[K structList](vals []interface{}) []K {
	targetStruct := []K{}
	temporaryVariable, _ := json.Marshal(vals)
	err := json.Unmarshal(temporaryVariable, &targetStruct)
	if err != nil {
		log.Fatalf("error unmarshaling")
	}
	return targetStruct
}

func mapInterfaceToType[K V3](val interface{}) K {
	return K(val.(string))
}
