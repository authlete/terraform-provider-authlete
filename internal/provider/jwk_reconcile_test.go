package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"testing"
)

func Test_simple_creation(t *testing.T) {

	jwks := ""
	key := map[string]interface{}{
		"kid":      "kid1",
		"alg":      "RS256",
		"use":      "sig",
		"generate": true,
		"key_size": 2048,
		"crv":      "",
		"n":        "",
	}

	newKey := single_key_test(t, key, jwks)
	if newKey.N == key["n"] {
		t.Error("attribute `", key["n"], "` should be populated, but ", newKey.N, " string is found")
	}
}

func Test_minimal_atts_creation(t *testing.T) {

	jwks := ""
	key := map[string]interface{}{

		"alg":      "PS256",
		"use":      "sig",
		"generate": true,
		"key_size": 2048,
		"crv":      "",
		"n":        "",
	}

	vals := []interface{}{key}
	diags := new(diag.Diagnostics)
	var diags2 diag.Diagnostics
	_, diags2 = calcUpdatedJWKS(vals, jwks, *diags)

	if !diags2.HasError() {
		t.Error("A key was generated without kid")
	}

	key = map[string]interface{}{
		"kid":      "kid1",
		"use":      "sig",
		"generate": true,
		"key_size": 2048,
		"crv":      "",
		"n":        "",
	}
	vals = []interface{}{key}
	_, diags2 = calcUpdatedJWKS(vals, jwks, *diags)

	if !diags2.HasError() {
		t.Error("A key was generated without alg")
	}

	key = map[string]interface{}{
		"kid":      "kid1",
		"alg":      "PS256",
		"generate": true,
		"key_size": 2048,
		"crv":      "",
		"n":        "",
	}
	vals = []interface{}{key}
	_, diags2 = calcUpdatedJWKS(vals, jwks, *diags)

	if !diags2.HasError() {
		t.Error("A key was generated without use")
	}
	key = map[string]interface{}{
		"alg":             "PS256",
		"use":             "sig",
		"pem_certificate": rsaCertWithoutChain,
	}
	vals = []interface{}{key}
	_, diags2 = calcUpdatedJWKS(vals, jwks, *diags)

	if !diags2.HasError() {
		t.Error("A key was loaded from pem without kid")
	}
	key = map[string]interface{}{
		"kid":             "kid1",
		"use":             "sig",
		"pem_certificate": rsaCertWithoutChain,
	}
	vals = []interface{}{key}
	_, diags2 = calcUpdatedJWKS(vals, jwks, *diags)

	if !diags2.HasError() {
		t.Error("A key was loaded from pem without alg")
	}
	key = map[string]interface{}{
		"kid":             "kid1",
		"alg":             "RS256",
		"pem_certificate": rsaCertWithoutChain,
	}
	vals = []interface{}{key}
	_, diags2 = calcUpdatedJWKS(vals, jwks, *diags)

	if !diags2.HasError() {
		t.Error("A key was loaded from pem without use")
	}
}

func Test_simple_update(t *testing.T) {

	jwks := `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "use": "sig",
            "kid": "kid1",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "alg": "PS256",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        }
    ]
}
`
	key := map[string]interface{}{
		"kid": "kid1",
		"alg": "PS256",
		"use": "sig",
		"p":   "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
		"kty": "RSA",
		"q":   "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
		"d":   "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
		"e":   "AQAB",
		"qi":  "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
		"dp":  "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
		"dq":  "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
		"n":   "123teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w",
		"crv": "",
		"k":   "",
		"x":   "",
		"y":   "",
		"x5c": []interface{}{},
	}

	single_key_test_with_n(t, key, jwks)

}

func Test_random_with_kid_no_update(t *testing.T) {

	jwks := `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "use": "sig",
            "kid": "kid1",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "alg": "PS256",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        }
    ]
}
`
	key := map[string]interface{}{
		"kid":      "kid1",
		"alg":      "PS256",
		"use":      "sig",
		"generate": true,
		"key_size": 2048,
	}

	newKey := single_key_test(t, key, jwks)
	if newKey.N != "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w" {
		t.Error("attribute n should not be changed, but ", newKey.N, " string is found")
	}

}

func Test_random_same_kid_dif_alg_update(t *testing.T) {

	jwks := `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "use": "sig",
            "kid": "kid1",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "alg": "RS256",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        }
    ]
}
`
	key := map[string]interface{}{
		"kid":      "kid1",
		"alg":      "PS256",
		"use":      "sig",
		"generate": true,
		"key_size": 2048,

		"p":   "",
		"kty": "",
		"q":   "",
		"d":   "",
		"e":   "",
		"qi":  "",
		"dp":  "",
		"dq":  "",
		"n":   "",
		"crv": "",
		"k":   "",
		"x":   "",
		"y":   "",
		"x5c": []interface{}{},
	}
	newKey := single_key_test(t, key, jwks)
	if newKey.N == key["n"] {
		t.Error("attribute `", key["n"], "` should be changed, but ", newKey.N, " string is found")
	}
}

func Test_simple_no_kid_no_alg_no_use(t *testing.T) {

	jwks := ``
	key := map[string]interface{}{
		"p":   "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
		"kty": "RSA",
		"q":   "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
		"d":   "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
		"e":   "AQAB",
		"qi":  "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
		"dp":  "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
		"dq":  "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
		"n":   "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w",
		"kid": "",
		"alg": "",
		"use": "",
		"crv": "",
		"k":   "",
		"x":   "",
		"y":   "",
		"x5c": []interface{}{},
	}
	single_key_test_with_n(t, key, jwks)

	jwksUpdate := `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "use": "sig",
            "kid": "kid1",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "alg": "RS256",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        }
    ]
}
`
	single_key_test_with_n(t, key, jwksUpdate)

	jwksUpdate = `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "123teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        }
    ]
}
`
	single_key_test_with_n(t, key, jwksUpdate)

}

func Test_simple_no_kid_with_alg_and_use(t *testing.T) {

	jwks := ``
	key := map[string]interface{}{
		"p":   "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
		"kty": "RSA",
		"q":   "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
		"d":   "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
		"e":   "AQAB",
		"qi":  "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
		"dp":  "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
		"dq":  "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
		"n":   "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w",
		"use": "sig",
		"alg": "RS256",
		"kid": "",
		"crv": "",
		"k":   "",
		"x":   "",
		"y":   "",
		"x5c": []interface{}{},
	}
	single_key_test_with_n(t, key, jwks)

	jwks = `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "use": "sig",
            "alg": "RS256",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        }
    ]
}`
	single_key_test_with_n(t, key, jwks)

	jwksUpdate := `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "use": "sig",
            "alg": "PS256",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        }
    ]
}
`
	single_key_test_with_n(t, key, jwksUpdate)

}

func Test_2_keys_no_kid_no_alg_no_use(t *testing.T) {

	jwks := ``
	key := map[string]interface{}{
		"p":   "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
		"kty": "RSA",
		"q":   "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
		"d":   "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
		"e":   "AQAB",
		"qi":  "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
		"dp":  "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
		"dq":  "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
		"n":   "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w",
		"kid": "",
		"alg": "",
		"use": "",
		"crv": "",
		"k":   "",
		"x":   "",
		"y":   "",
		"x5c": []interface{}{},
	}
	key2 := map[string]interface{}{
		"p":   "5LYmVqXNxTXNTI8uWyUNcJV7ykSIE047FB50AjRQgpnzDKMsEaT9KLMo6BsjayAPUfGSxIQQTDK28Gdy8Ci4E2E0x_YtXVIZZ7qQG9bJmraPukFDssYPXD8Z2ZWm8h0_--iy3QBNIEPO9WX3e50bYQLXlcyBgJKel1hz6p_6zUU",
		"kty": "RSA",
		"q":   "23SYz0lkn_8f_-iDgbrNJvixzqHVfuO9MV70OFFPdqlQadOwJ9dupV81W7Hk_bgWD5Kph1mSiCsIPAEI_99QdHYBqGaxUK5eWrkXC-F3um0jsbHXvRYTePS6K-QJAWTItjwWMZDpJFLnvUXLqYAeCCiEZLKFHEaN_Tr4ZI1RHhE",
		"d":   "WW3F57zLEwTtoG5M5cOWvdflxBfbggd6rhuUwkqNjQqpO6CauN67GtTXOs6lbQlwsF2f6sjo_j0sHrL_zAh5kd1-IE1JTPJuHnNz5foW-EuQICkNd9BZNHuGGbi08PfXkmeeojTVPZWrChjdmiMffBJMBf1Os1ksxP5wnJO4FWNehscFV4TXgTOa2eoY19aoceolBHxncErjzGmTqSE0WVfYBU4jgGH-cPMmdL9nDo99MCtKceBgvsqEE8tvBWEhgcY5qjP1g2js-ZAXZ43hHHbQrIbzz928c1dWg_yjyzXCjuklkhpRHHy76XL4z0Keq739gk2cBiNU4qcK6Z8tQQ",
		"e":   "AQAB",
		"qi":  "0jQ9gCJIAQiYKHtZHuknYYUm0bitZJ88gZ8x46GYYebCX62a_ZbFr_hvgX36uFC8L5ezEp8GHd8C48_sHXaWrwGVTgVfof0iVeIIlcvXZiZ9WAFHba5Gn5DCuO531VkBP_vpckNtH3oo4cFJUpDIC9zoQN-cvGEQssnI4ljhcF8",
		"dp":  "DoOctTz6bPx4Fda0S2ZzjuR9oZ1twUPireks1YL6ZP9eFDw6rLf6tN2ByBEI02CKeFnLRZtX6W4CfAkkmycKX3h4wAPYZyaxpAqL4KhlzOKvBlPj9vFowiLjAhLkMFM430SqLSo6usRy2tHovbh_p01l3wTGZyFm3RXo7UfPw70",
		"dq":  "O92kyfdFgfgA7LirFzq0OEtjhfDT4teRhuRWTv6vZLlvfE8JIPU989LzJV50D1qmef0STh_7PzYt-uB1agerVPnUHfJVsKLAjpMrXExXcv3O3Oyc47IgAcERAGQmqMCrmDrv-vmDACu1mAZwNn8CsksLQsUIVtxQY6IwnI2IcWE",
		"n":   "xA_92ta4cntgcxBKkyYSHcYE6mPeV84qD-5ZRM4LqRh4J1dPzWH_CX8zJiaoypPPaCpGErpL9E2b4x10lsLF__DKXNgzQ-9YBL2f1wNfq525e4-n5vmLAeYbmn2e4gHn4uA6dJ5KPDqd1IvLTnW7ot_gsWLtYRILi6lY6QsHAZYi4CAvvp_F_Mzb84LI-uCQPyoNHflxCrUN6bNaABHv8y8x9o6-2OGH9XP8f0e6q_7Om94MLXm-0ihljrwa7R5MjVjPPLEvmiZ93ivInWa8mkRiNPXPZ9FOsufhOiucmbWSqPmRG8qsVqMs-1hslOqshwHLYVgtiGt5Q_mx94q3lQ",
		"kid": "",
		"alg": "",
		"use": "",
		"crv": "",
		"k":   "",
		"x":   "",
		"y":   "",
		"x5c": []interface{}{},
	}
	vals := []interface{}{key, key2}
	diags := new(diag.Diagnostics)
	newJWKS, _ := calcUpdatedJWKS(vals, jwks, *diags)

	if len(newJWKS) != 2 {
		t.Error("Not every key were created")
	}

	jwksUpdate := `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        },
		{
			"p": "5LYmVqXNxTXNTI8uWyUNcJV7ykSIE047FB50AjRQgpnzDKMsEaT9KLMo6BsjayAPUfGSxIQQTDK28Gdy8Ci4E2E0x_YtXVIZZ7qQG9bJmraPukFDssYPXD8Z2ZWm8h0_--iy3QBNIEPO9WX3e50bYQLXlcyBgJKel1hz6p_6zUU",
			"kty": "RSA",
			"q": "23SYz0lkn_8f_-iDgbrNJvixzqHVfuO9MV70OFFPdqlQadOwJ9dupV81W7Hk_bgWD5Kph1mSiCsIPAEI_99QdHYBqGaxUK5eWrkXC-F3um0jsbHXvRYTePS6K-QJAWTItjwWMZDpJFLnvUXLqYAeCCiEZLKFHEaN_Tr4ZI1RHhE",
			"d": "WW3F57zLEwTtoG5M5cOWvdflxBfbggd6rhuUwkqNjQqpO6CauN67GtTXOs6lbQlwsF2f6sjo_j0sHrL_zAh5kd1-IE1JTPJuHnNz5foW-EuQICkNd9BZNHuGGbi08PfXkmeeojTVPZWrChjdmiMffBJMBf1Os1ksxP5wnJO4FWNehscFV4TXgTOa2eoY19aoceolBHxncErjzGmTqSE0WVfYBU4jgGH-cPMmdL9nDo99MCtKceBgvsqEE8tvBWEhgcY5qjP1g2js-ZAXZ43hHHbQrIbzz928c1dWg_yjyzXCjuklkhpRHHy76XL4z0Keq739gk2cBiNU4qcK6Z8tQQ",
			"e": "AQAB",
			"qi": "0jQ9gCJIAQiYKHtZHuknYYUm0bitZJ88gZ8x46GYYebCX62a_ZbFr_hvgX36uFC8L5ezEp8GHd8C48_sHXaWrwGVTgVfof0iVeIIlcvXZiZ9WAFHba5Gn5DCuO531VkBP_vpckNtH3oo4cFJUpDIC9zoQN-cvGEQssnI4ljhcF8",
			"dp": "DoOctTz6bPx4Fda0S2ZzjuR9oZ1twUPireks1YL6ZP9eFDw6rLf6tN2ByBEI02CKeFnLRZtX6W4CfAkkmycKX3h4wAPYZyaxpAqL4KhlzOKvBlPj9vFowiLjAhLkMFM430SqLSo6usRy2tHovbh_p01l3wTGZyFm3RXo7UfPw70",
			"dq": "O92kyfdFgfgA7LirFzq0OEtjhfDT4teRhuRWTv6vZLlvfE8JIPU989LzJV50D1qmef0STh_7PzYt-uB1agerVPnUHfJVsKLAjpMrXExXcv3O3Oyc47IgAcERAGQmqMCrmDrv-vmDACu1mAZwNn8CsksLQsUIVtxQY6IwnI2IcWE",
			"n": "xA_92ta4cntgcxBKkyYSHcYE6mPeV84qD-5ZRM4LqRh4J1dPzWH_CX8zJiaoypPPaCpGErpL9E2b4x10lsLF__DKXNgzQ-9YBL2f1wNfq525e4-n5vmLAeYbmn2e4gHn4uA6dJ5KPDqd1IvLTnW7ot_gsWLtYRILi6lY6QsHAZYi4CAvvp_F_Mzb84LI-uCQPyoNHflxCrUN6bNaABHv8y8x9o6-2OGH9XP8f0e6q_7Om94MLXm-0ihljrwa7R5MjVjPPLEvmiZ93ivInWa8mkRiNPXPZ9FOsufhOiucmbWSqPmRG8qsVqMs-1hslOqshwHLYVgtiGt5Q_mx94q3lQ"
        }
    ]
}
`
	newJWKS, _ = calcUpdatedJWKS(vals, jwksUpdate, *diags)

	if len(newJWKS) != 2 {
		t.Error("The update has included or removed a key")
	}

	jwksUpdate = `
{
    "keys": [
        {
            "p": "-kp5lDJtK8S7m5PrciXtEKYDY0Jqk3CKAmNRmY-QjoTgddv-T9CSuSI8AgGfJOyviWD7q9lipqS6NfprMUh5pFEfP14S_13kQOO0E0dHh2w-tjFMDXJExwviMUyUsLITtMi9OqVUAKT6qQJg_sRCGWkkunENF0aJIi7YRNUYXEc",
            "kty": "RSA",
            "q": "ugaTPzv8t1PQElQnPPGKAWLnGez5ekHQccFIzurMCrjJJvl8ck5ctDLukMXp8v2SD7J2ub_hZeA0uCU0_OExduYjt2z3P1ucVFyLDG4SngVPaQEeT8T8GK0yETdK-gGH7jUzNT45tgzIGCNCUx5qZsKsmw949KyhD03a5W-pS80",
            "d": "eK0Paug2RRC9WQbimZ_fozib9ZumdjBDDJgSuhoJ8T7DW1viko142-Ueh7v28FZ0NRC1VQU7MlAtX_k3IY1qiADOe_hz0M32OQuAue5qWVoPEFtFdUHICbZCsItIaZXOmxHkFdVOcIT46PLvQMBiZkkB89-qHkON1Yrbf6YK5hCBdtw3svcoeLEQqyj_fk4I1zO_zLnYRg7hNIuL7Z-cYUtvj_GoLduuwR_J0GtT3gbXJTm873ywfdRKBFChJjPAixWG-lujcwe_duyYGFfZT3DQU3B-TdmQtrSKNfjWyYcs0liBA3ZlLpBIvSw41Jjy5sMXGNn-Maf-NHuzdvxv4Q",
            "e": "AQAB",
            "qi": "n2jG3aGVubLDEGrAzRKKGU2mWz2Mfp8MGkJHYs12P8TLGTLzAXjsIFmTXXH4YKzdg3LWFKqm55HEOWpi-Wfk0IxwZNvH3qxn459YIwIsX42kT-aFsDyHtWsY-1Bz0531u2A4tTIisO1vt77SqA9T3UiaNf71jSU41HvIgDtVjeM",
            "dp": "q__0DuicZ2CaAG8ldNslT7SWTWb98HZ9EOkJ0Xp8P8SGr9fPqy_NNJaXIFXW9LwGYWUZbl5EUfqP0LpXYZXJqibpT1Wpvn3adtFEFZ99Q04axn-YIQFuzE6ZUYGsCMVHj4wHpj6pPIwjiXOODmX2epnr2IgKE_2wDaKdkqfSRs8",
            "dq": "QCTgRR-kJnrJ9mf6F7OZyJyX34KtC5ECFRd2yZKAxPmusre4R5npsWEWjekQoG77HFqHQcl-KSjERPLfcIseCUeV7TuvjbNDFnvKnoCd_ssJ9MUj9JGR89hUuUb9nXNFsce6XpOURsflfx05U3vbaI-cAOO263dTGfnYjuCP2ck",
            "n": "123teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w"
        },
		{
			"p": "5LYmVqXNxTXNTI8uWyUNcJV7ykSIE047FB50AjRQgpnzDKMsEaT9KLMo6BsjayAPUfGSxIQQTDK28Gdy8Ci4E2E0x_YtXVIZZ7qQG9bJmraPukFDssYPXD8Z2ZWm8h0_--iy3QBNIEPO9WX3e50bYQLXlcyBgJKel1hz6p_6zUU",
			"kty": "RSA",
			"q": "23SYz0lkn_8f_-iDgbrNJvixzqHVfuO9MV70OFFPdqlQadOwJ9dupV81W7Hk_bgWD5Kph1mSiCsIPAEI_99QdHYBqGaxUK5eWrkXC-F3um0jsbHXvRYTePS6K-QJAWTItjwWMZDpJFLnvUXLqYAeCCiEZLKFHEaN_Tr4ZI1RHhE",
			"d": "WW3F57zLEwTtoG5M5cOWvdflxBfbggd6rhuUwkqNjQqpO6CauN67GtTXOs6lbQlwsF2f6sjo_j0sHrL_zAh5kd1-IE1JTPJuHnNz5foW-EuQICkNd9BZNHuGGbi08PfXkmeeojTVPZWrChjdmiMffBJMBf1Os1ksxP5wnJO4FWNehscFV4TXgTOa2eoY19aoceolBHxncErjzGmTqSE0WVfYBU4jgGH-cPMmdL9nDo99MCtKceBgvsqEE8tvBWEhgcY5qjP1g2js-ZAXZ43hHHbQrIbzz928c1dWg_yjyzXCjuklkhpRHHy76XL4z0Keq739gk2cBiNU4qcK6Z8tQQ",
			"e": "AQAB",
			"qi": "0jQ9gCJIAQiYKHtZHuknYYUm0bitZJ88gZ8x46GYYebCX62a_ZbFr_hvgX36uFC8L5ezEp8GHd8C48_sHXaWrwGVTgVfof0iVeIIlcvXZiZ9WAFHba5Gn5DCuO531VkBP_vpckNtH3oo4cFJUpDIC9zoQN-cvGEQssnI4ljhcF8",
			"dp": "DoOctTz6bPx4Fda0S2ZzjuR9oZ1twUPireks1YL6ZP9eFDw6rLf6tN2ByBEI02CKeFnLRZtX6W4CfAkkmycKX3h4wAPYZyaxpAqL4KhlzOKvBlPj9vFowiLjAhLkMFM430SqLSo6usRy2tHovbh_p01l3wTGZyFm3RXo7UfPw70",
			"dq": "O92kyfdFgfgA7LirFzq0OEtjhfDT4teRhuRWTv6vZLlvfE8JIPU989LzJV50D1qmef0STh_7PzYt-uB1agerVPnUHfJVsKLAjpMrXExXcv3O3Oyc47IgAcERAGQmqMCrmDrv-vmDACu1mAZwNn8CsksLQsUIVtxQY6IwnI2IcWE",
			"n": "xA_92ta4cntgcxBKkyYSHcYE6mPeV84qD-5ZRM4LqRh4J1dPzWH_CX8zJiaoypPPaCpGErpL9E2b4x10lsLF__DKXNgzQ-9YBL2f1wNfq525e4-n5vmLAeYbmn2e4gHn4uA6dJ5KPDqd1IvLTnW7ot_gsWLtYRILi6lY6QsHAZYi4CAvvp_F_Mzb84LI-uCQPyoNHflxCrUN6bNaABHv8y8x9o6-2OGH9XP8f0e6q_7Om94MLXm-0ihljrwa7R5MjVjPPLEvmiZ93ivInWa8mkRiNPXPZ9FOsufhOiucmbWSqPmRG8qsVqMs-1hslOqshwHLYVgtiGt5Q_mx94q3lQ"
        }
    ]
}
`
	newJWKS, _ = calcUpdatedJWKS(vals, jwksUpdate, *diags)

	if len(newJWKS) != 2 {
		t.Error("The update has included or removed a key")
	}

	if !((newJWKS[0].N == "xA_92ta4cntgcxBKkyYSHcYE6mPeV84qD-5ZRM4LqRh4J1dPzWH_CX8zJiaoypPPaCpGErpL9E2b4x10lsLF__DKXNgzQ-9YBL2f1wNfq525e4-n5vmLAeYbmn2e4gHn4uA6dJ5KPDqd1IvLTnW7ot_gsWLtYRILi6lY6QsHAZYi4CAvvp_F_Mzb84LI-uCQPyoNHflxCrUN6bNaABHv8y8x9o6-2OGH9XP8f0e6q_7Om94MLXm-0ihljrwa7R5MjVjPPLEvmiZ93ivInWa8mkRiNPXPZ9FOsufhOiucmbWSqPmRG8qsVqMs-1hslOqshwHLYVgtiGt5Q_mx94q3lQ" ||
		newJWKS[0].N == "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w") &&
		(newJWKS[1].N == "xA_92ta4cntgcxBKkyYSHcYE6mPeV84qD-5ZRM4LqRh4J1dPzWH_CX8zJiaoypPPaCpGErpL9E2b4x10lsLF__DKXNgzQ-9YBL2f1wNfq525e4-n5vmLAeYbmn2e4gHn4uA6dJ5KPDqd1IvLTnW7ot_gsWLtYRILi6lY6QsHAZYi4CAvvp_F_Mzb84LI-uCQPyoNHflxCrUN6bNaABHv8y8x9o6-2OGH9XP8f0e6q_7Om94MLXm-0ihljrwa7R5MjVjPPLEvmiZ93ivInWa8mkRiNPXPZ9FOsufhOiucmbWSqPmRG8qsVqMs-1hslOqshwHLYVgtiGt5Q_mx94q3lQ" ||
			newJWKS[1].N == "teCKCxzmw1sT6MI0nHkwpYzXUhDKb-WV3sRw2-13n8iLwGndF2JiQQe2-tuD1BbqkVNaiDjNG7CXX4eQ0YSInY_N3nXKUOCahaBm5L-2krxMpG6erPBG5xlLO07G1BIiPsjF2y1_gSN_INOEb-b2aGOE3jeENv8bEGrrCF5yMHF28cf76DOmkwhO3VIp8S8BfLue7viC-DfJDpDZnR3-b4_C0Iqbf3AUCj-qutlxpPG6HY32ODr7ghyvTHRvYuXCW-p0tVfld2tbShEagnZwLv61LmrATMC2X2mPLnrVvUZJKXEavGNma_54ab88sj6GPr07837n3vL-b5gne2mx2w")) {
		t.Error("the resulting key was not updated")
	}
}

func single_key_test_with_n(t *testing.T, key map[string]interface{}, jwks string) {
	newKey := single_key_test(t, key, jwks)
	if newKey.N != key["n"] {
		t.Error("attribute `", key["n"], "` should be populated, but ", newKey.N, " string is found")
	}
}
func single_key_test(t *testing.T, key map[string]interface{}, jwks string) JWKStruct {
	vals := []interface{}{key}
	diags := new(diag.Diagnostics)
	newJWKS, _ := calcUpdatedJWKS(vals, jwks, *diags)

	if len(newJWKS) != 1 {
		t.Error("The key array should have one element, but ", len(newJWKS), " elements are present")
	}

	if newJWKS[0].Kid != key["kid"] {
		t.Error("kid `", key["kid"], "` was expected, but ", newJWKS[0].Kid, " is found")
	}

	if newJWKS[0].Alg != key["alg"] {
		t.Error("alg `", key["alg"], "` was expected, but ", newJWKS[0].Alg, " is found")
	}

	if newJWKS[0].Use != key["use"] {
		t.Error("use `", key["use"], "` was expected, but ", newJWKS[0].Use, " is found")
	}

	return newJWKS[0]
}
