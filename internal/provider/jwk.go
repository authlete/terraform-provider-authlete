package provider

import (
	"encoding/json"
	"errors"
	"fmt"

	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/x25519"
)

func createJWKSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"kid": {
					Type:     schema.TypeString,
					Required: true,
				},
				"alg": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						"RS256", "RS384", "RS512",
						"PS256", "PS384", "PS512",
						"ES256", "ES384", "ES512", "EdDSA",
						"RSA-OAEP", "RSA-OAEP-256",
						"A128KW", "A192KW", "A256KW",
						"dir",
						"ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW",
						"A128GCMKW", "A192GCMKW", "A256GCMKW",
						"PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
					}, false),
				},
				"use": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.StringInSlice([]string{
						"sig", "enc",
					}, false),
				},
				"crv": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.StringInSlice([]string{
						"P-256", "P-384", "P-521",
						"secp256k1", "Ed25519", "X25519",
					}, false),
				},
				"generate": {
					Type:     schema.TypeBool,
					Optional: true,
					Default:  false,
				},
				"key_size": {
					Type:     schema.TypeInt,
					Optional: true,
					Default:  2048,
				},
				"kty": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"d": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"dp": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"dq": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"e": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"k": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"n": {
					Type:     schema.TypeString,
					Optional: true,
				},
				"p": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"q": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"qi": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"x": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
				"x5c": {
					Type:     schema.TypeList,
					Optional: true,
					Elem: &schema.Schema{
						Type: schema.TypeString,
					},
				},
				"y": {
					Type:      schema.TypeString,
					Optional:  true,
					Sensitive: true,
				},
			},
		},
	}
}

type JWKStruct struct {
	Kid string   `json:"kid,omitempty"`
	Alg string   `json:"alg,omitempty"`
	Use string   `json:"use,omitempty"`
	Kty string   `json:"kty,omitempty"`
	Crv string   `json:"crv,omitempty"`
	D   string   `json:"d,omitempty"`
	Dp  string   `json:"dp,omitempty"`
	Dq  string   `json:"dq,omitempty"`
	E   string   `json:"e,omitempty"`
	K   string   `json:"k,omitempty"`
	N   string   `json:"n,omitempty"`
	P   string   `json:"p,omitempty"`
	Q   string   `json:"q,omitempty"`
	Qi  string   `json:"qi,omitempty"`
	X   string   `json:"x,omitempty"`
	X5c []string `json:"x5c,omitempty"`
	Y   string   `json:"y,omitempty"`
}

func generateOKPKey(crv string) (jwk.Key, error) {

	if crv == "Ed25519" {
		_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		return jwk.New(privateKey)
	} else if crv == "X25519" {
		_, privateKey, _ := x25519.GenerateKey(rand.Reader)
		return jwk.New(privateKey)
	}

	return nil, errors.New("generating keys using " + crv + " is not implemented")
}

func generateECKey(crv string) (jwk.Key, error) {

	var curve elliptic.Curve
	if crv == "P-256" {
		curve = elliptic.P256()
	} else if crv == "P-521" {
		curve = elliptic.P521()
	} else if crv == "P-384" {
		curve = elliptic.P521()
	} else {
		return nil, errors.New("generating keys using " + crv + " is not implemented")
	}

	raw, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate new ECDSA privatre key: %s\n", err)
		return nil, err
	}

	return jwk.New(raw)

}

func generateRSAKey(keySize int) (jwk.Key, error) {
	raw, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		fmt.Printf("failed to generate new RSA privatre key: %s\n", err)
		return nil, err
	}

	return jwk.New(raw)
}

func getAsString(newKey jwk.Key, key string) (string, bool) {
	valRaw, rootValue := newKey.Get(key)

	val := valRaw.([]byte)
	return string(val), rootValue
}

func mapJWKS(vals *schema.Set, diags diag.Diagnostics) (string, diag.Diagnostics) {

	var keysArray = []JWKStruct{}

	for _, aKey := range vals.List() {
		var val1 = aKey.(map[string]interface{})

		//fmt.Println(val1["kid"].(string))
		var element JWKStruct
		if val1["generate"] != nil && val1["generate"].(bool) {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Creating a new key",
				Detail:   "Creating a new key with id " + val1["kid"].(string),
			})
			var alg = val1["alg"].(string)
			var crv = val1["crv"].(string)

			if alg == "RS256" || alg == "PS256" ||
				alg == "RS384" || alg == "PS384" ||
				alg == "RS512" || alg == "PS512" ||
				alg == "RSA-OAEP" || alg == "RSA-OAEP-256" {

				if val1["d"] != nil || val1["e"] != nil ||
					val1["n"] != nil || val1["p"] != nil || val1["q"] != nil {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Warning,
						Summary:  "Random key configured and key provided",
						Detail:   "key with id " + val1["kid"].(string) + " is a random key but some key attributes are provided. Those key attributes will be overwritten.",
					})
				}

				keySize := val1["key_size"].(int)

				rsaKey, err := generateRSAKey(keySize)
				if err != nil {
					diags = append(diags, diag.FromErr(err)...)
				} else {

					jsonContent, _ := json.Marshal(rsaKey)
					element = JWKStruct{
						Kid: val1["kid"].(string),
						Alg: val1["alg"].(string),
						Use: val1["use"].(string),
					}

					err = json.Unmarshal(jsonContent, &element)
					if err != nil {
						diags = append(diags, diag.FromErr(err)...)
					}
				}

			} else if crv == "Ed25519" || crv == "X25519" {
				if val1["d"] != nil || val1["x"] != nil {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Warning,
						Summary:  "Random key configured and key provided",
						Detail:   "key with id " + val1["kid"].(string) + " is a random key but some key attributes are provided. Those key attributes will be overwritten.",
					})
				}

				okpKey, err := generateOKPKey(crv)

				if err != nil {
					diags = append(diags, diag.FromErr(err)...)
				} else {
					jsonContent, _ := json.Marshal(okpKey)
					element = JWKStruct{
						Kid: val1["kid"].(string),
						Alg: val1["alg"].(string),
						Use: val1["use"].(string),
						Crv: val1["crv"].(string),
					}

					err = json.Unmarshal(jsonContent, &element)
					if err != nil {
						diags = append(diags, diag.FromErr(err)...)
					}

				}
			} else if alg == "ES256" || alg == "ES256K" || alg == "ES384" || alg == "ES512" ||
				alg == "ECDH-ES" || alg == "ECDH-ES+A128KW" || alg == "ECDH-ES+A192KW" || alg == "ECDH-ES+A256KW" {

				if val1["d"] != nil || val1["x"] != nil {
					diags = append(diags, diag.Diagnostic{
						Severity: diag.Warning,
						Summary:  "Random key configured and key provided",
						Detail:   "key with id " + val1["kid"].(string) + " is a random key but some key attributes are provided. Those key attributes will be overwritten.",
					})
				}

				ecKey, err := generateECKey(crv)

				if err != nil {
					diags = append(diags, diag.FromErr(err)...)

				} else {

					jsonContent, _ := json.Marshal(ecKey)
					element = JWKStruct{
						Kid: val1["kid"].(string),
						Alg: val1["alg"].(string),
						Use: val1["use"].(string),
						Crv: val1["crv"].(string),
					}

					err = json.Unmarshal(jsonContent, &element)
					if err != nil {
						diags = append(diags, diag.FromErr(err)...)
					}

				}
			}

		} else {

			element = JWKStruct{
				Kid: val1["kid"].(string),
				Alg: val1["alg"].(string),
				Use: val1["use"].(string),
				Kty: val1["kty"].(string),
				Crv: val1["crv"].(string),
				D:   val1["d"].(string),
				Dp:  val1["dp"].(string),
				Dq:  val1["dq"].(string),
				E:   val1["e"].(string),
				K:   val1["k"].(string),
				N:   val1["n"].(string),
				P:   val1["p"].(string),
				Q:   val1["q"].(string),
				Qi:  val1["qi"].(string),
				X:   val1["x"].(string),
				X5c: mapArray(val1["x5c"].([]interface{})),
				Y:   val1["y"].(string),
			}
		}
		keysArray = append(keysArray, element)

	}

	var toFormat = map[string][]JWKStruct{"keys": keysArray}

	jsonString, _ := json.Marshal(toFormat)

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Creating a JWKS",
		Detail:   "Creating a new JWKS " + string(jsonString),
	})
	var toReturn = string(jsonString)
	//fmt.Println(toReturn)
	return toReturn, diags
}

func mapArray(x5c []interface{}) []string {
	var x5cAux = make([]string, len(x5c))
	for i, v := range x5c {
		x5cAux[i] = v.(string)
	}
	return x5cAux
}

func updateJWKS(vals *schema.Set, jwks string, diags diag.Diagnostics) (string, diag.Diagnostics) {

	var keysArray = []JWKStruct{}

	var keysMap map[string][]JWKStruct
	json.Unmarshal([]byte(jwks), &keysMap)

	//var keys = keysMap["keys"]

	for _, aKey := range vals.List() {
		var val1 = aKey.(map[string]interface{})

		fmt.Println(val1["kid"].(string))

		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "Creating a new key",
			Detail:   "Creating a new key with id " + val1["kid"].(string),
		})
		var element = JWKStruct{
			Kid: val1["kid"].(string),
			Alg: val1["alg"].(string),
			Use: val1["use"].(string),
			Kty: val1["kty"].(string),
			Crv: val1["crv"].(string),
			D:   val1["d"].(string),
			Dp:  val1["dp"].(string),
			Dq:  val1["dq"].(string),
			E:   val1["e"].(string),
			K:   val1["k"].(string),
			N:   val1["n"].(string),
			P:   val1["p"].(string),
			Q:   val1["q"].(string),
			Qi:  val1["qi"].(string),
			X:   val1["x"].(string),
			X5c: mapArray(val1["x5c"].([]interface{})),
			Y:   val1["y"].(string),
		}

		keysArray = append(keysArray, element)

	}

	var toReturn string
	var toFormat = map[string][]JWKStruct{"keys": keysArray}

	jsonString, _ := json.Marshal(toFormat)

	fmt.Println(string(jsonString))
	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "Creating a JWKS",
		Detail:   "Creating a new JWKS " + string(jsonString),
	})
	toReturn = string(jsonString)
	return toReturn, diags
}
