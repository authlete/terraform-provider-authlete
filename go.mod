module github.com/authlete/terraform-provider-authlete

go 1.15

require (
	github.com/authlete/authlete-go v1.1.4
	github.com/hashicorp/terraform-plugin-docs v0.8.1
	github.com/hashicorp/terraform-plugin-log v0.4.0
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.16.0
	github.com/lestrrat-go/jwx v1.2.24
)

//replace github.com/authlete/authlete-go => ../authlete-go
