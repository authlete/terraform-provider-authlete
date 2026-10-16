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

// KeyType returns the kty an algorithm requires, for the algorithms that
// require exactly one. The second result is false for an algorithm this
// package does not constrain.
func KeyType(alg string) (string, bool) {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"),
		alg == "RSA1_5", strings.HasPrefix(alg, "RSA-OAEP"):
		return "RSA", true
	case strings.HasPrefix(alg, "ES"), strings.HasPrefix(alg, "ECDH-ES"):
		return "EC", true
	case alg == "EdDSA":
		return "OKP", true
	}
	return "", false
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
