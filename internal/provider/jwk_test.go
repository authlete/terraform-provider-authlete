package provider

import (
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"reflect"
	"testing"
)

func Test_parse_rsa(t *testing.T) {

	expected := JWKStruct{
		Kid: "rsa1",
		Alg: "alg1",
		Use: "sig",
		Kty: "RSA",
		D:   "qEgVnYm62SCf0WYy8Q5SncOCV8Y-aOQ5MbcTwWgh5J5nn3wnTvq_efQiGwXekdcPhiI0oQz_USHEOGwPhiQtY_grhutnzK7wIDvrzrNtDU8jnNXn5XZAbLYinerChICTjGZqdyoHElHPLPpYdAqD2Gxn_0LEw7BRr67_sox2x0W9W3EIzWQhO-1a_Ur3VRTqYfO-dA737cB3cr2Snvbt1Y3AtCxgNahWXlIMH8pzWhnMcImf4Gdr5wGwFvoO2KX3ak7OJd9skAJbsNwrYNaWLc8-DNYl-Dsl-S1jEvz_9V6_X1yxktB_BGKAAm_pm-Szk0esVh0GaX6OwJkxKzOpcQ",
		Dp:  "T8u01EO-rMrx4oR2OnAVg8of6Z-anxFoc_63RGsxlnNvNuKhIbzaxl97MJ5GTKaLWYzQ7Hc_sYOJ2i5-M-eyUYfU3COX4vJ0_H90YJYsemcI1QmaPiQ6da2AZJwXLz_b4x4xTupdOfKpkhiT2yMOvVy8JWGf5GppfWaJ6H43LAE",
		Dq:  "XPsQmfFR5VgERHFmzZMz7MOyao0rH6zU9vykvUdj58bdsJ5S_xNrV9QoHhZn9iCVk0TTaIvlWoGrkx9UJ3vnGOL09xklC2hwFTzRC5UhF7mpQaP7Wbl0uKIFS-E-_HH1QLBeOllfidWzq788JsVMSHhyHkAJcNrLTl2a3Pq1Gd0",
		E:   "AQAB",
		N:   "71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq-P8u1aceyPotR3AW49BIJ4VzPdTSx-rMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7-fcYyf5AIhcZClt5OrFpTboHYadJ5l_rjpRSNxE7i7b34Bi1A_HEgmA3GuPV8yf8nDRwGtzBC-nd5tX7gugDbVw_5fF-HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa-UdkR9ceill1Pz0ID-SLdO2Jt-DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQ",
		P:   "_DKf_-iHtdjfYEagYah-RSGgPmntz45QqMelLKwfoA_fVlgADc1jmGxEJj2EewXTwRal1836Lqg9NNgBNvyFcn7kyi2t6GyK2e5uOQTm67Kbmxd_TjQOisPT-gfZbIgJ6c2vLJarHW5EAmWatmgF7l0niETOS_qkDAy7ceDJNm0",
		Q:   "8vDHRkSvfaBNsZKk2_EdR_Bljaq24b0ItDcxHwnCSQr3VGo4qIHYsuM_suiJYTgEsX0KwtPgwMNdxYxwYKxDxtNtqk-B0TW64YDLOm6KBAyf8XA0uMedomWm9fkRlP0Bq5I2Q1X8QaiMiFewnex_JTqpGh546SahvOoPJt7nAtU",
		Qi:  "91xsKekO9sAv2-eKBxUEheHUFHpQz4kmoZY5FpujUYKsSvTQ8OzaZ1S3hoFXwPGd7b6V0oICZhANVTbfPTSq48w63L3MU8x1f4CJjcgaYrH7FR0K3YIaG3818T8971SIzCxhGKVrpnf550XlroXAtq1HaP0tFnO_ggAbOwd1HWY",
	}
	key := rsaPrivateKeyPem
	cert := ""
	kid := "rsa1"
	alg := "alg1"
	use := "sig"

	validatePemLoad(t, cert, key, kid, alg, use, expected)

	// parsing a private key and a cert
	expected = JWKStruct{
		Kid:     "rsa1",
		Alg:     "alg1",
		Use:     "sig",
		Kty:     "RSA",
		D:       "qEgVnYm62SCf0WYy8Q5SncOCV8Y-aOQ5MbcTwWgh5J5nn3wnTvq_efQiGwXekdcPhiI0oQz_USHEOGwPhiQtY_grhutnzK7wIDvrzrNtDU8jnNXn5XZAbLYinerChICTjGZqdyoHElHPLPpYdAqD2Gxn_0LEw7BRr67_sox2x0W9W3EIzWQhO-1a_Ur3VRTqYfO-dA737cB3cr2Snvbt1Y3AtCxgNahWXlIMH8pzWhnMcImf4Gdr5wGwFvoO2KX3ak7OJd9skAJbsNwrYNaWLc8-DNYl-Dsl-S1jEvz_9V6_X1yxktB_BGKAAm_pm-Szk0esVh0GaX6OwJkxKzOpcQ",
		Dp:      "T8u01EO-rMrx4oR2OnAVg8of6Z-anxFoc_63RGsxlnNvNuKhIbzaxl97MJ5GTKaLWYzQ7Hc_sYOJ2i5-M-eyUYfU3COX4vJ0_H90YJYsemcI1QmaPiQ6da2AZJwXLz_b4x4xTupdOfKpkhiT2yMOvVy8JWGf5GppfWaJ6H43LAE",
		Dq:      "XPsQmfFR5VgERHFmzZMz7MOyao0rH6zU9vykvUdj58bdsJ5S_xNrV9QoHhZn9iCVk0TTaIvlWoGrkx9UJ3vnGOL09xklC2hwFTzRC5UhF7mpQaP7Wbl0uKIFS-E-_HH1QLBeOllfidWzq788JsVMSHhyHkAJcNrLTl2a3Pq1Gd0",
		E:       "AQAB",
		N:       "71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq-P8u1aceyPotR3AW49BIJ4VzPdTSx-rMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7-fcYyf5AIhcZClt5OrFpTboHYadJ5l_rjpRSNxE7i7b34Bi1A_HEgmA3GuPV8yf8nDRwGtzBC-nd5tX7gugDbVw_5fF-HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa-UdkR9ceill1Pz0ID-SLdO2Jt-DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQ",
		P:       "_DKf_-iHtdjfYEagYah-RSGgPmntz45QqMelLKwfoA_fVlgADc1jmGxEJj2EewXTwRal1836Lqg9NNgBNvyFcn7kyi2t6GyK2e5uOQTm67Kbmxd_TjQOisPT-gfZbIgJ6c2vLJarHW5EAmWatmgF7l0niETOS_qkDAy7ceDJNm0",
		Q:       "8vDHRkSvfaBNsZKk2_EdR_Bljaq24b0ItDcxHwnCSQr3VGo4qIHYsuM_suiJYTgEsX0KwtPgwMNdxYxwYKxDxtNtqk-B0TW64YDLOm6KBAyf8XA0uMedomWm9fkRlP0Bq5I2Q1X8QaiMiFewnex_JTqpGh546SahvOoPJt7nAtU",
		Qi:      "91xsKekO9sAv2-eKBxUEheHUFHpQz4kmoZY5FpujUYKsSvTQ8OzaZ1S3hoFXwPGd7b6V0oICZhANVTbfPTSq48w63L3MU8x1f4CJjcgaYrH7FR0K3YIaG3818T8971SIzCxhGKVrpnf550XlroXAtq1HaP0tFnO_ggAbOwd1HWY",
		X:       "",
		Y:       "",
		X5c:     []string{"MIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcwNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+rMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTboHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2Jt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQIDAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueMIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREEDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxjmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/crAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzFAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3PQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYRlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmeaHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56PpZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9QSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZDm/0k4YruLQ7bFY+/xjRBH+741916"},
		X5t:     "SZQ3eVG5qqIgWYwbb5rzQDEWA4s=",
		X5ts256: "xIFtb8juze-EPXBpJHFIXESG2aSP_lM41iFsz0lQwzo=",
	}
	key = rsaPrivateKeyPem
	cert = rsaCertWithoutChain
	kid = "rsa1"
	alg = "alg1"
	use = "sig"

	validatePemLoad(t, cert, key, kid, alg, use, expected)

	//parsing only a certificate
	expected = JWKStruct{
		Kid:     "rsa1",
		Alg:     "alg1",
		Use:     "sig",
		Kty:     "RSA",
		D:       "",
		Dp:      "",
		Dq:      "",
		E:       "AQAB",
		N:       "71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq-P8u1aceyPotR3AW49BIJ4VzPdTSx-rMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7-fcYyf5AIhcZClt5OrFpTboHYadJ5l_rjpRSNxE7i7b34Bi1A_HEgmA3GuPV8yf8nDRwGtzBC-nd5tX7gugDbVw_5fF-HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa-UdkR9ceill1Pz0ID-SLdO2Jt-DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQ",
		P:       "",
		Q:       "",
		Qi:      "",
		X:       "",
		Y:       "",
		X5c:     []string{"MIIEwTCCAqmgAwIBAgIID+K+XgJff98wDQYJKoZIhvcNAQELBQAwUDELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTEPMA0GA1UEAwwGcnNhX2NhMB4XDTIyMDcwNjE5NTEwMFoXDTIzMDcwNjE5NTEwMFowUzELMAkGA1UEBhMCYnIxCzAJBgNVBAgTAkVTMRAwDgYDVQQHEwdWaXRvcmlhMREwDwYDVQQKEwhBdXRobGV0ZTESMBAGA1UEAwwJc2VydmVyX29wMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq+P8u1aceyPotR3AW49BIJ4VzPdTSx+rMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7+fcYyf5AIhcZClt5OrFpTboHYadJ5l/rjpRSNxE7i7b34Bi1A/HEgmA3GuPV8yf8nDRwGtzBC+nd5tX7gugDbVw/5fF+HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa+UdkR9ceill1Pz0ID+SLdO2Jt+DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQIDAQABo4GbMIGYMAwGA1UdEwEB/wQCMAAwHQYDVR0OBBYEFGrTFrTNXRXUDJwCxueMIhznWSw9MAsGA1UdDwQEAwID6DATBgNVHSUEDDAKBggrBgEFBQcDATAUBgNVHREEDTALgglzZXJ2ZXJfb3AwEQYJYIZIAYb4QgEBBAQDAgZAMB4GCWCGSAGG+EIBDQQRFg94Y2EgY2VydGlmaWNhdGUwDQYJKoZIhvcNAQELBQADggIBACBKbO/kmaQ2HGxjmy4Vnap5D45ydgOVzFy1juw/QhyyX+Cth71CONt/39tJlE12vJcqcZxV1JMnY3JI5rrX62YxuczCrU5W2+Xn5Jo7lY0mFvGbi89bXQruHIDMnLpyXw4Ri5UkaMTuG/crAj26pMGnCcWFhos7knKQQ4Yu2zwYymhNWlVAbNxTPvM5fcTHSNB2nxU/Q8UqOIzFAKL1iCBPlF3BDaLijQxA6aGYzouiefnzy3ODjOuIy3qM4yfD1gh9jHrRs+h+TJZ3PQ4xZfBkgVMkQcOcsjWEOZf+uXQTVMHF7Y4c41u8VG3IljLCS0ipD86nLq9wbTYRlA3to3IRCj9PwGCZIUALqmmmgRnw834P90mp8GsLtTbVTGO/zLRI46MHeeLiJmeaHVItOpqn5ahpiauqrdXpoGTlecqmfAkyREn64xkTwGqDqL5X0NMIXre+7ydZb56PpZFb8CBviEGmTW6hYvsqHp7E3phPoOs72zww1jTipCC43DrGbYk/FoBjj6SORHpE456Zaj7rboJortVwkI8uwzg799wimTWvz2kGQT4+zDvQMa38XrEuAO8fhqf+2I9QSSLrHMO4MyflFnuLf8KLC3ochRzCJDbkB9K8s/DiELK3pj7NZXwUzT5pxF3n5oZDm/0k4YruLQ7bFY+/xjRBH+741916"},
		X5t:     "SZQ3eVG5qqIgWYwbb5rzQDEWA4s=",
		X5ts256: "xIFtb8juze-EPXBpJHFIXESG2aSP_lM41iFsz0lQwzo=",
	}
	key = ""
	cert = rsaCertWithoutChain
	kid = "rsa1"
	alg = "alg1"
	use = "sig"

	validatePemLoad(t, cert, key, kid, alg, use, expected)

	expected = JWKStruct{
		Kid: "rsa1",
		Alg: "alg1",
		Use: "sig",
		Kty: "RSA",
		D:   "",
		Dp:  "",
		Dq:  "",
		E:   "AQAB",
		N:   "71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq-P8u1aceyPotR3AW49BIJ4VzPdTSx-rMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7-fcYyf5AIhcZClt5OrFpTboHYadJ5l_rjpRSNxE7i7b34Bi1A_HEgmA3GuPV8yf8nDRwGtzBC-nd5tX7gugDbVw_5fF-HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa-UdkR9ceill1Pz0ID-SLdO2Jt-DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQ",
		P:   "",
		Q:   "",
		Qi:  "",
		X:   "",
		Y:   "",
		X5c: []string{"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"},
		X5t:     "SZQ3eVG5qqIgWYwbb5rzQDEWA4s=",
		X5ts256: "xIFtb8juze-EPXBpJHFIXESG2aSP_lM41iFsz0lQwzo=",
	}
	key = ""
	cert = rsaCertChain
	kid = "rsa1"
	alg = "alg1"
	use = "sig"

	validatePemLoad(t, cert, key, kid, alg, use, expected)

	//parsing a key with a cert chain
	expected = JWKStruct{
		Kid: "rsa1",
		Alg: "alg1",
		Use: "sig",
		Kty: "RSA",
		D:   "qEgVnYm62SCf0WYy8Q5SncOCV8Y-aOQ5MbcTwWgh5J5nn3wnTvq_efQiGwXekdcPhiI0oQz_USHEOGwPhiQtY_grhutnzK7wIDvrzrNtDU8jnNXn5XZAbLYinerChICTjGZqdyoHElHPLPpYdAqD2Gxn_0LEw7BRr67_sox2x0W9W3EIzWQhO-1a_Ur3VRTqYfO-dA737cB3cr2Snvbt1Y3AtCxgNahWXlIMH8pzWhnMcImf4Gdr5wGwFvoO2KX3ak7OJd9skAJbsNwrYNaWLc8-DNYl-Dsl-S1jEvz_9V6_X1yxktB_BGKAAm_pm-Szk0esVh0GaX6OwJkxKzOpcQ",
		Dp:  "T8u01EO-rMrx4oR2OnAVg8of6Z-anxFoc_63RGsxlnNvNuKhIbzaxl97MJ5GTKaLWYzQ7Hc_sYOJ2i5-M-eyUYfU3COX4vJ0_H90YJYsemcI1QmaPiQ6da2AZJwXLz_b4x4xTupdOfKpkhiT2yMOvVy8JWGf5GppfWaJ6H43LAE",
		Dq:  "XPsQmfFR5VgERHFmzZMz7MOyao0rH6zU9vykvUdj58bdsJ5S_xNrV9QoHhZn9iCVk0TTaIvlWoGrkx9UJ3vnGOL09xklC2hwFTzRC5UhF7mpQaP7Wbl0uKIFS-E-_HH1QLBeOllfidWzq788JsVMSHhyHkAJcNrLTl2a3Pq1Gd0",
		E:   "AQAB",
		N:   "71UPBn2cS7qP89sdIlWEv2KrsTopLuWeIpbzB98V8U1OIvb0YPcCHtpLq-P8u1aceyPotR3AW49BIJ4VzPdTSx-rMmBV0iNv4y289eEZa5Ipvk9TFtEmf7vR6ZMmM1xK7-fcYyf5AIhcZClt5OrFpTboHYadJ5l_rjpRSNxE7i7b34Bi1A_HEgmA3GuPV8yf8nDRwGtzBC-nd5tX7gugDbVw_5fF-HDBGcB4u7Fm6fK6T4C37ohxvI6RWphB3AuEa-UdkR9ceill1Pz0ID-SLdO2Jt-DnxNCNqBa0ezLY70g0no6YkvLcnzbaNh82yE28p1IhweF4CP4b6NyPDIisQ",
		P:   "_DKf_-iHtdjfYEagYah-RSGgPmntz45QqMelLKwfoA_fVlgADc1jmGxEJj2EewXTwRal1836Lqg9NNgBNvyFcn7kyi2t6GyK2e5uOQTm67Kbmxd_TjQOisPT-gfZbIgJ6c2vLJarHW5EAmWatmgF7l0niETOS_qkDAy7ceDJNm0",
		Q:   "8vDHRkSvfaBNsZKk2_EdR_Bljaq24b0ItDcxHwnCSQr3VGo4qIHYsuM_suiJYTgEsX0KwtPgwMNdxYxwYKxDxtNtqk-B0TW64YDLOm6KBAyf8XA0uMedomWm9fkRlP0Bq5I2Q1X8QaiMiFewnex_JTqpGh546SahvOoPJt7nAtU",
		Qi:  "91xsKekO9sAv2-eKBxUEheHUFHpQz4kmoZY5FpujUYKsSvTQ8OzaZ1S3hoFXwPGd7b6V0oICZhANVTbfPTSq48w63L3MU8x1f4CJjcgaYrH7FR0K3YIaG3818T8971SIzCxhGKVrpnf550XlroXAtq1HaP0tFnO_ggAbOwd1HWY",
		X:   "",
		Y:   "",
		X5c: []string{"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"},
		X5t:     "SZQ3eVG5qqIgWYwbb5rzQDEWA4s=",
		X5ts256: "xIFtb8juze-EPXBpJHFIXESG2aSP_lM41iFsz0lQwzo=",
	}
	key = rsaPrivateKeyPem
	cert = rsaCertChain
	kid = "rsa1"
	alg = "alg1"
	use = "sig"

	validatePemLoad(t, cert, key, kid, alg, use, expected)

}

func validatePemLoad(t *testing.T, cert string, key string, kid string, alg string, use string, expected JWKStruct) {
	diags := diag.Diagnostics{}
	entry := make(map[string]interface{}, 0)
	entry["pem_certificate"] = cert
	entry["pem_private_key"] = key
	entry["kid"] = kid
	entry["alg"] = alg
	entry["use"] = use
	jwk, _ := loadPem(entry, diags)
	if expected.Kid != jwk.Kid {
		t.Error("Got Kid ", jwk.Kid, " and the expect value is ", expected.Kid)
	}
	if expected.Alg != jwk.Alg {
		t.Error("Got Alg ", jwk.Alg, " and the expect value is ", expected.Alg)
	}
	if expected.Use != jwk.Use {
		t.Error("Got Use ", jwk.Use, " and the expect value is ", expected.Use)
	}
	if expected.Kty != jwk.Kty {
		t.Error("Got Kty ", jwk.Kty, " and the expect value is ", expected.Kty)
	}
	if expected.D != jwk.D {
		t.Error("Got D ", jwk.D, " and the expect value is ", expected.D)
	}
	if expected.Dp != jwk.Dp {
		t.Error("Got Dp ", jwk.Dp, " and the expect value is  ", expected.Dp)
	}
	if expected.Dq != jwk.Dq {
		t.Error("Got Dq ", jwk.Dq, " and the expect value is ", expected.Dq)
	}
	if expected.E != jwk.E {
		t.Error("Got E ", jwk.E, " and the expect value is ", expected.E)
	}
	if expected.N != jwk.N {
		t.Error("Got N ", jwk.N, " and the expect value is ", expected.N)
	}
	if expected.P != jwk.P {
		t.Error("Got P ", jwk.P, " and the expect value is ", expected.P)
	}
	if expected.Q != jwk.Q {
		t.Error("Got Q ", jwk.Q, "and the expect value is ", expected.Q)
	}
	if expected.Qi != jwk.Qi {
		t.Error("Got Qi ", jwk.Qi, "and the expect value is  ", expected.Qi)
	}
	if expected.X5ts256 != jwk.X5ts256 {
		t.Error("Got X5ts256 ", jwk.X5ts256, "and the expect value is  ", expected.X5ts256)
	}
	if expected.X5t != jwk.X5t {
		t.Error("Got X5t ", jwk.X5t, "and the expect value is  ", expected.X5t)
	}

	if expected.X != jwk.X {
		t.Error("Got X ", jwk.X, "and the expect value is  ", expected.X)
	}
	if expected.Y != jwk.Y {
		t.Error("Got Y ", jwk.Y, "and the expect value is  ", expected.Y)
	}
	if !reflect.DeepEqual(expected.X5c, jwk.X5c) {
		t.Error("Got X5c ", jwk.X5c, "and the expect value is  ", expected.X5c)
	}
}
