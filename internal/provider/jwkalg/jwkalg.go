// Package jwkalg holds the pairings between a JWK algorithm and the key that
// can perform it.
//
// Two places need them and they must not drift apart: jwk_from_pem, which
// checks the alg against a parsed key, and the jwks attribute validator, which
// checks it against the kty and crv members of a document the user may have
// written by hand.
//
// Only the pairings RFC 7518 fixes are recorded. An algorithm this package
// does not know is not an error anywhere: the registry is extensible, and a
// provider that rejected everything it had not been taught would break working
// configurations the day Authlete supported something new.
package jwkalg

import "strings"

// sigCurve pairs each ECDSA signing algorithm with the single curve RFC 7518
// section 3.1 defines it for. No other combination is valid.
var sigCurve = map[string]string{
	"ES256": "P-256",
	"ES384": "P-384",
	"ES512": "P-521",
}

// SigCurve returns the curve an ECDSA signing algorithm requires. The second
// result is false for anything that is not one of ES256, ES384 or ES512.
func SigCurve(alg string) (string, bool) {
	crv, ok := sigCurve[alg]
	return crv, ok
}

// SigAlg returns the ECDSA signing algorithm for a curve, the reverse of
// SigCurve.
func SigAlg(crv string) (string, bool) {
	for alg, c := range sigCurve {
		if c == crv {
			return alg, true
		}
	}
	return "", false
}

// okpCurve pairs each OKP algorithm with the curve that performs it. Ed25519
// signs and X25519 performs key agreement, and neither can do the other's job,
// so an OKP kty alone does not say an algorithm is possible.
var okpCurve = map[string]string{
	"EdDSA":          "Ed25519",
	"ECDH-ES":        "X25519",
	"ECDH-ES+A128KW": "X25519",
	"ECDH-ES+A192KW": "X25519",
	"ECDH-ES+A256KW": "X25519",
}

// OKPCurve returns the curve an algorithm needs when the key is an OKP key.
// The second result is false for an algorithm that is not an OKP one, and for
// ECDH-ES on an EC key the caller never reaches this, since kty decides first.
func OKPCurve(alg string) (string, bool) {
	crv, ok := okpCurve[alg]
	return crv, ok
}

// KeyType returns the kty an algorithm requires, for the algorithms that
// require exactly one. The second result is false for an algorithm this
// package does not constrain.
func KeyType(alg string) (string, bool) {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"),
		alg == "RSA1_5", strings.HasPrefix(alg, "RSA-OAEP"):
		return "RSA", true
	case strings.HasPrefix(alg, "ES"):
		return "EC", true
	case alg == "EdDSA":
		return "OKP", true
	}
	return "", false
}

// Purpose returns whether an algorithm signs or encrypts, for the algorithms
// where that is fixed. The second result is false for an algorithm this
// package does not constrain.
//
// The key management cases are tested first because "RSA1_5" and "RSA-OAEP"
// both begin with "RS", which would otherwise read as a signing algorithm.
func Purpose(alg string) (string, bool) {
	switch {
	case alg == "RSA1_5", strings.HasPrefix(alg, "RSA-OAEP"), strings.HasPrefix(alg, "ECDH-ES"):
		return "enc", true
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"),
		strings.HasPrefix(alg, "ES"), strings.HasPrefix(alg, "HS"),
		alg == "EdDSA":
		return "sig", true
	}
	return "", false
}

// octKeyBytes gives the exact key length, in bytes, that an algorithm needs
// from a symmetric key. RFC 7518 fixes these: AES key wrap takes a key the
// size of its AES variant, and sections 4.4 and 4.7 make that exact rather
// than a minimum.
var octKeyBytes = map[string]int{
	"A128KW": 16, "A192KW": 24, "A256KW": 32,
	"A128GCMKW": 16, "A192GCMKW": 24, "A256GCMKW": 32,
}

// octKeyMinBytes gives the smallest key an algorithm will accept. RFC 7518
// section 3.2 requires an HMAC key at least as long as the hash output, and
// says nothing about an upper bound.
var octKeyMinBytes = map[string]int{
	"HS256": 32, "HS384": 48, "HS512": 64,
}

// OctKeySize returns the length in bytes a symmetric key must have for an
// algorithm, and whether that length is exact or a minimum. The third result
// is false for an algorithm with no fixed requirement, such as "dir", where
// the size follows from the content encryption algorithm instead.
func OctKeySize(alg string) (size int, exact bool, known bool) {
	if n, ok := octKeyBytes[alg]; ok {
		return n, true, true
	}
	if n, ok := octKeyMinBytes[alg]; ok {
		return n, false, true
	}
	return 0, false, false
}

// OctAlgs returns the algorithms a symmetric key can perform for a given use.
func OctAlgs(use string) []string {
	if use == "enc" {
		return []string{
			"dir",
			"A128KW", "A192KW", "A256KW",
			"A128GCMKW", "A192GCMKW", "A256GCMKW",
			"PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW",
		}
	}
	return []string{"HS256", "HS384", "HS512"}
}

// IsHMAC reports whether alg is a symmetric HMAC algorithm. Publishing a
// public key under one is the shape of an algorithm confusion attack: a
// verifier that trusts the published alg could be led to treat the public key
// as the shared HMAC secret.
func IsHMAC(alg string) bool { return strings.HasPrefix(alg, "HS") }

// IsAsymmetric reports whether a kty names a public and private key pair,
// which is every key type this provider can publish. A symmetric "oct" key
// carries a secret and is excluded, since HMAC is correct for one.
func IsAsymmetric(kty string) bool {
	switch kty {
	case "RSA", "EC", "OKP":
		return true
	}
	return false
}
