package provider

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/x25519"
)

func createJWKSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
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

func generateOKPKey(newKey map[string]interface{}) (JWKStruct, error) {

	var okpKey jwk.Key
	var crv = newKey["crv"].(string)
	var err error
	if crv == "Ed25519" {
		_, privateKey, _ := ed25519.GenerateKey(rand.Reader)
		okpKey, err = jwk.New(privateKey)
	} else if crv == "X25519" {
		_, privateKey, _ := x25519.GenerateKey(rand.Reader)
		okpKey, err = jwk.New(privateKey)
	}

	var element = JWKStruct{
		Kid: newKey["kid"].(string),
		Alg: newKey["alg"].(string),
		Use: newKey["use"].(string),
		Crv: newKey["crv"].(string),
		Kty: "OKP",
	}

	if err != nil {
		return element, err
	} else {
		jsonContent, _ := json.Marshal(okpKey)

		err = json.Unmarshal(jsonContent, &element)

		return element, err

	}

}

func generateECKey(newKey map[string]interface{}) (JWKStruct, error) {

	var crv = newKey["crv"].(string)

	element := JWKStruct{
		Kid: newKey["kid"].(string),
		Alg: newKey["alg"].(string),
		Use: newKey["use"].(string),
		Crv: newKey["crv"].(string),
		Kty: "EC",
	}

	var curve elliptic.Curve
	if crv == "P-256" {
		curve = elliptic.P256()
	} else if crv == "P-521" {
		curve = elliptic.P521()
	} else if crv == "P-384" {
		curve = elliptic.P521()
	} else {
		return element, errors.New("generating keys using " + crv + " is not implemented")
	}

	raw, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate new ECDSA privatre key: %s\n", err)
		return element, err
	}

	ecKey, err := jwk.New(raw)

	if err != nil {
		return element, err

	} else {

		jsonContent, _ := json.Marshal(ecKey)

		err = json.Unmarshal(jsonContent, &element)
		return element, err
	}

}

func generateRSAKey(keyMap map[string]interface{}) (JWKStruct, error) {

	element := JWKStruct{
		Kid: keyMap["kid"].(string),
		Alg: keyMap["alg"].(string),
		Use: keyMap["use"].(string),
		Kty: "RSA",
	}

	keySize, _ := keyMap["key_size"].(int)
	raw, err := rsa.GenerateKey(rand.Reader, keySize)

	rsaKey, err := jwk.New(raw)

	if err != nil {
		return element, err
	} else {

		jsonContent, _ := json.Marshal(rsaKey)

		err = json.Unmarshal(jsonContent, &element)
		return element, err
	}
}

func generateKey(keyDef map[string]interface{}, diags diag.Diagnostics) JWKStruct {
	var alg = keyDef["alg"].(string)
	var crv = keyDef["crv"].(string)
	var element JWKStruct
	var err error
	if alg == "RS256" || alg == "PS256" ||
		alg == "RS384" || alg == "PS384" ||
		alg == "RS512" || alg == "PS512" ||
		alg == "RSA-OAEP" || alg == "RSA-OAEP-256" {

		if keyDef["d"] != "" || keyDef["e"] != "" ||
			keyDef["n"] != "" || keyDef["p"] != "" || keyDef["q"] != "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Random key configured and key provided",
				Detail:   "key with id " + keyDef["kid"].(string) + " is a random key but some key attributes are provided. Those key attributes will be overwritten.",
			})
		}

		element, err = generateRSAKey(keyDef)
		if err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}

	} else if alg == "ES256" || alg == "ES384" || alg == "ES512" ||
		alg == "ECDH-ES" || alg == "ECDH-ES+A128KW" || alg == "ECDH-ES+A192KW" || alg == "ECDH-ES+A256KW" {

		if keyDef["d"] != "" || keyDef["x"] != "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Random key configured and key provided",
				Detail:   "key with id " + keyDef["kid"].(string) + " is a random key but some key attributes are provided. Those key attributes will be overwritten.",
			})
		}

		element, err = generateECKey(keyDef)
		if err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}
	} else if crv == "Ed25519" || crv == "X25519" {
		// EC curves

		if keyDef["d"] != "" || keyDef["x"] != "" {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "Random key configured and key provided",
				Detail:   "key with id " + keyDef["kid"].(string) + " is a random key but some key attributes are provided. Those key attributes will be overwritten.",
			})
		}

		element, err = generateOKPKey(keyDef)

		if err != nil {
			diags = append(diags, diag.FromErr(err)...)
		}

	} else if alg == "ES256K" {
		// bitcoin curve
		// TODO: implement the key generation using
		// https://pkg.go.dev/github.com/decred/dcrd/dcrec/secp256k1/v4#section-documentation

	}

	return element
}

func getAsString(newKey jwk.Key, key string) (string, bool) {
	valRaw, rootValue := newKey.Get(key)

	val := valRaw.([]byte)
	return string(val), rootValue
}

func mapJWKS(vals []interface{}, diags diag.Diagnostics) (string, diag.Diagnostics) {

	var keysArray = []JWKStruct{}

	for _, aKey := range vals {
		var val1 = aKey.(map[string]interface{})

		// fmt.Println(val1["kid"].(string))
		var element JWKStruct

		if val1["generate"] != nil && val1["generate"].(bool) {
			element = generateKey(val1, diags)
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

	return string(jsonString), diags
}

func mapArray(x5c []interface{}) []string {
	var x5cAux = make([]string, len(x5c))
	for i, v := range x5c {
		x5cAux[i] = v.(string)
	}
	return x5cAux
}

func findKey(kid string, existingKeys []JWKStruct, diags diag.Diagnostics) interface{} {

	for _, aKey := range existingKeys {
		diags = append(diags, diag.Diagnostic{
			Severity: diag.Warning,
			Summary:  "key: " + aKey.Kid,
			Detail:   "key: " + aKey.Kid + " => " + kid,
		})
		if aKey.Kid == kid {
			diags = append(diags, diag.Diagnostic{
				Severity: diag.Warning,
				Summary:  "found key: " + aKey.Kid,
				Detail:   "key: " + aKey.Kid + " => " + kid,
			})
			return aKey
		}
	}
	return nil
}

func findLocalKey(kid string, existingKeys []interface{}) map[string]interface{} {

	for _, aKey := range existingKeys {
		localKey := aKey.(map[string]interface{})
		if localKey["kid"] == kid {

			return localKey
		}
	}
	return nil
}

func updateJWKS(vals []interface{}, jwks string, diags diag.Diagnostics) (string, diag.Diagnostics) {

	var keysArray = []JWKStruct{}

	var keysMap map[string][]JWKStruct
	json.Unmarshal([]byte(jwks), &keysMap)

	var keys = keysMap["keys"]

	diags = append(diags, diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  "existing keys",
		Detail:   " keys: " + fmt.Sprint(keys),
	})

	for _, aKey := range vals {
		var val1 = aKey.(map[string]interface{})

		var element JWKStruct

		if val1["generate"] != nil && val1["generate"].(bool) {
			var raw = findKey(val1["kid"].(string), keys, diags)
			if raw == nil {
				element = generateKey(val1, diags)
			} else {
				element = raw.(JWKStruct)
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

	var toReturn string
	var toFormat = map[string][]JWKStruct{"keys": keysArray}

	jsonString, _ := json.Marshal(toFormat)

	toReturn = string(jsonString)
	return toReturn, diags
}

func mapJWKFromDTO(localKeys []interface{}, jwks string) []interface{} {

	var serverKeysMap map[string][]JWKStruct
	json.Unmarshal([]byte(jwks), &serverKeysMap)

	var serverKeys = serverKeysMap["keys"]

	result := make([]interface{}, len(serverKeys))

	for i, aKey := range serverKeys {
		localKey := findLocalKey(aKey.Kid, localKeys)
		if localKey != nil && localKey["generate"] == true {
			result[i] = localKey
		} else {
			element := make(map[string]interface{})
			element["kid"] = aKey.Kid
			element["alg"] = aKey.Alg
			if aKey.Use != "" {
				element["use"] = aKey.Use
			}
			if aKey.Kty != "" {
				element["kty"] = aKey.Kty
			}
			if aKey.Crv != "" {
				element["crv"] = aKey.Crv
			}
			if aKey.D != "" {
				element["d"] = aKey.D
			}
			if aKey.Dp != "" {
				element["dp"] = aKey.Dp
			}
			if aKey.Dq != "" {
				element["dq"] = aKey.Dq
			}
			if aKey.E != "" {
				element["e"] = aKey.E
			}
			if aKey.K != "" {
				element["k"] = aKey.K
			}
			if aKey.N != "" {
				element["n"] = aKey.N
			}
			if aKey.P != "" {
				element["p"] = aKey.P
			}
			if aKey.Q != "" {
				element["q"] = aKey.Q
			}
			if aKey.Qi != "" {
				element["qi"] = aKey.Qi
			}
			if aKey.X != "" {
				element["x"] = aKey.X
			}
			element["x5c"] = aKey.X5c
			if aKey.Y != "" {
				element["y"] = aKey.Y
			}
			result[i] = element
		}

	}
	return result
}
