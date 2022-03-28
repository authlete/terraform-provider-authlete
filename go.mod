module github.com/authlete/terraform-provider-authlete

go 1.15

require (
	github.com/authlete/authlete-go v1.1.4
	github.com/hashicorp/terraform-plugin-docs v0.5.1
	github.com/hashicorp/terraform-plugin-log v0.2.1
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.10.1
	github.com/lestrrat-go/jwx v1.2.20
)

//replace github.com/authlete/authlete-go => ../authlete-go
