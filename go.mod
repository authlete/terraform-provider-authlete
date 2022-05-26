module github.com/authlete/terraform-provider-authlete

go 1.15

require (
	github.com/authlete/openapi-for-go v0.2.0
	github.com/hashicorp/terraform-plugin-docs v0.8.1
	github.com/hashicorp/terraform-plugin-log v0.4.0
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.16.0
	github.com/lestrrat-go/jwx v1.2.25
	golang.org/x/net v0.0.0-20220524220425-1d687d428aca // indirect
	golang.org/x/oauth2 v0.0.0-20220524215830-622c5d57e401 // indirect
	google.golang.org/appengine v1.6.7 // indirect
)

//replace github.com/authlete/openapi-for-go => ../openapi-for-go
