terraform {
  required_providers {
      authlete = {
      source = "dcreado/authlete"
      version = ">= 1.0"
    }
  }
}

provider "authlete" {
	service_owner_key = "162395379605"
	service_owner_secret = "SyfOC-1kECcVn0AEd0RJ_A2cQYz1Qia1-OWnRaLPhCw"
}

resource "authlete_service" "prod" {
  issuer = "https://test.com"
  service_name = "Test API 4"
  description = "Terraform test service 4"
  clients_per_developer = 10
  supported_token_auth_methods = ["CLIENT_SECRET_BASIC"]
  access_token_sign_alg = "RS256"
  access_token_signature_key_id = "kid1"
  jwk {
	  kid = "kid1"
	  alg = "RS256" 
	  use = "sig" 
	  kty = "RSA"
    p   = "2Rv6rAY__R6zfebmBX_aqMBtuGEccYJcWBMppaumGk8eFLfdQvwwvJ400T7qUt_JnXByzUlbZIIAn5cmUSI8pdFz_XFhjvIRKJp2pq5R2LjJlXBRT5_PAV9u0YQFk_WOu65qOr6vIrIoDceljYZNbNTqUKy7S102oaodBKu6QD8"
    q   = "uX_xV2KsEE83Sxb8JKAST0K9HLocQ2uS7zSp40TB0ng5OOhDwgQoZMcPj_u3JYWq65Pc0GAaWaFoj2TVHsshwPTklgNLnVSyx4CbHFFZCatjxG6bx2wrq4nVCj2xP1QqBvy2qq-OH8O9bS1Fk1AmHk4DR2VmDWyfRs3dQH7o2rc"
    d   =  "nDGEHBvPRfXE4q8fbK1bCGCmlt2KONEHn8-79LaZktgg-kn_Onw--k8nGZHyW1zmWFzPmREuwsKVHvyOLot1aa-wDXarObDQ4KNotOyjGyeW-NsovMO5OHQlr45AvDyEvyn_NYpScwE2yYPGXaslu4daK2XKzufjDbMtlOJQ4eovkxlFoqV0YCwBqRoRBShwN51sgg4iFrcP3U79yIch3vlm8dT3HbHiv0OlY0Umfcw1El34kyiVv0w7dEmu-AZ-r4dZ853-17nZ_Rjw00eT8deRh8ls-W8U2iw_0aaz5cT-GjgcA1uDDtLA18iH8aGr0Rs1v-aHYQ7MCuXLKS97cQ"
    e   = "AQAB"
    qi  = "0jnmcjcE45bcrQ2XT2wqW0N-mtXscWIzVUfyYIJmkaFaIKK0zNCjsITXiJvAmblN_fEsxqWsd9Db-qEKBnRpUfPLm6etmaEeZmcMPRr9FEYSN-8V0D9dpkkdw8BFt6y9A7DL1leZJ7Il40FxPxZJ7lLBTdIvtAb0aZble-_fjgw"
    dp  = "NbTqKavSIHd7x2Va-XlLSftwKPA87QdmeJMk9kqj6FYyBsYFAhEIrWAliK2boayiX0P14jqHVTGjndbyL5fckNhjbQqjK41OGVE8kLcGoCn2E_WY562Ms7Y737BdAOD50guvU6DgCiEwL1h3566VcJqq7BIOsvH4Fb3TN9iTVlk"
    dq  = "d0Lp0GvxAf9cJlvdulJr0yeuXETPnQ0Rh9dNDoALORzwdUTnI1r2-Wv99m04X9hjflgvVI0lA9FBX0fNuaGRzvPj7wqpV7q3wopNr1QhsZTObOFMKFfEb-IK5S2qwnODHcDmVDDQaF25cPL1U3PpPfycIQ_xH9phQO1kPW4amVs"
    n   = "nVG5tR8IHJlTJHKjrwjDu46PlgJdaR9t5b9dm5L29OlukIs4BugZxat-7MHeV8e61tPjUXGrobT2tJPLWtu9q-NVVSZi3Rg63RBrXJqiuUVk_RDEPq8OAcig6d982r0ivzRJ9sCgIhHymjyGh2EAvATOfDsSMfYHu7lqPknEn7CQAHCekHt2n9p0-WWwsSftK2YFbwyYbq_N0idFG-xlWd5ymvd-CEScUyWlsreKgYKFdF-FrsCT2fzv2RTFf4MIc-_1rzgkys4EPtYTz590uRwhw7ZLovrHYutb9fzo9dBBfjD1BjacuT5pMv37B37RMcfFyM-Wmm1qi3e8l_GTCQ"
 
   } 
   jwk {
	kid = "kid2"
	alg = "RSA-OAEP" 
	use = "enc" 
	kty = "RSA"
  p   = "6Nee892NQ94ugHFzyFyXDFEL1r5cAFTphcYU9v1MipY8C74OWVOFQFRfZrHZ4Gwce1Qs1Q9dLd-J5x0fnaROQKqenL1OAM0l3ycLBs8WMldC4IHFIfOb7LSd8MkPAcYG-mCgsTbZq9fcVTub-AqykVoeQTqiqrKiYj1Fw3JKxec"
  q   = "qBCy69oOxZudiGvuNwJNdfj4TlCWXcb4LuLenktfuYBo98FVCfXBgCkfRUnuMZ6lNBlmm4tSiipV2YEJN3Uu7OJx9XzDFO98yaG9Yy2lYWvK0URKoE6GO_YMFdO33fJ5Wt3AUw1aa-fV1x9YspZJl-SSOlJzjVnGtxUbJ1UeR7c"
  d   = "QLnBrUhaUTbKI2mjk_8CCSOV4-2QT2CRFomWWIbfDbTUPQPGbrEbPf7NojuJnjNwri8Y5GykyoBGt5yR8SGn4Zmwe67DWPQt-ZH5AQULZoN7ykQPujWQb5DT7sj7bFP0YfckRE5G-7cmXQuAsJCkCcc0CEeQAyNt0ZYZWRviGg5qx5XwVBp_kfWmsBUzHzWeOsc35jk9Q2ZEbND1q8uyB-5dPLCB-mFd7Cz8TszC54xs-XZKJn1yWstLmE8mO6cmy3DIVM_QJ0cByHaoEMoz5RAl171AN9TovmLEHcZUOFpgJTs1M6AKtq1aZZvDwa9WnK7a8ugmOvg_JvBWD03mmQ"
  e   = "AQAB"
  qi  = "I7hbzxFXxUss7J8IatYLHAnHl_5eu3S_r5Y2HPYkJmasRtvYYtY9W6WzjND1686Ladz6RUmtrR-th96E0zsSTrjWw9wgkVrUcKu0Uegb-zS-MAQo6U6UV7Zz7_QtjphuGotsjjylNjh6asXLInriBNs6gQAk37FZts4oFev88MI"
  dp  = "eD7qWrxe-N6kGzb7-Uw_wV-VgpgaQR2Y37n1F7ymK6f8aIAFPwJP_XHVNt7ASxLp_pLw-DMQBuG7gPxcWHgC5Yh3kzB8ORO47C5olmKZ7vN7mR_LY4ZATxTTwAbFVkAjWGhQdFSEQyeeJPI80PMNVt04ZK1YVlkcXSmRfqbmkJ8"
  dq  = "no3Cfodl0D-TSxSn0_W0JkwP1bJpaWdA1NrrsuLhGBxw6uvV0mOrfcFN4wxwTxegO5qLFstFv1tZSq1ViKBg-NJZOIPPd3zIeWDBT0PM9i-_U9XdoYbzVLY3iJAIsrcCjhsOSkwathotv5mvECyAmW_mFGec5AmCU07yIxVGT9k"
  n   = "mNywhmlsFCh5bJ2hn2Fhu7-P4_y3z-OqFiDZllO5afW4-5co0ROFHJk--x8Wbu8SE_YaHxWwxBB4ExI5lMMkLKoh4z9LZ4Vnw1WdigKDXPYmd4VJNsEgdvrr52VCC9bmIbkY2QAyRwRa44LiknjRsXfHUMD-kTyeWePMQfQJbXo4o_xpHj0RzRf21hNMjXygsvnIJ7x4F9F3umZi5xUnugbncbbO-KRRIzTpT5MrmUe201w7h4ywdSkBGTZhSyIqfmSJfvsCNThD7eQKCi-B-AsoGGp_bB5dBcSZX03WwpSrg6xC9_8DkhZLmcyo-09gGSgAUYCBB8PzNs8TVGiJIQ"
        
   } 

jwk {
	kid = "kid9"
	alg = "RS256" 
	use = "sig" 
	generate = true
  key_size = 1024
}
jwk {
	kid = "kid13"
	alg = "RS256" 
	use = "sig" 
	generate = true
  key_size = 1024
}

jwk {
	kid = "kid4"
	alg = "ES256" 
	use = "sig" 
	generate = true
  crv = "P-256"
}
jwk {
	kid = "kid5"
	alg = "ECDH-ES" 
	use = "enc" 
	generate = true
  crv = "P-256"
}
jwk {
	kid = "kid6"
	alg = "ECDH-ES" 
	use = "sig" 
	generate = true
  crv = "P-256"
}
jwk {
	kid = "kid7"
	alg = "EdDSA" 
	use = "sig" 
	generate = true
  crv = "Ed25519"
}
  supported_scopes {
    name = "payment"
    description = "scope that grants the permission to 3rd party to start payment"

    attribute {
      key = "key1"
      value = "val1"
    }

    attribute {
      key = "fapi"
      value = "rw"
    }
  }

	supported_scopes {
		name = "openid"
	}
}