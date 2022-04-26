---
# Authlete Terraform provider
page_title: "Importing Services and Clients"
subcategory: ""
description: |-
  
---

# Authlete dedicated cloud server

The provider supports importing the Authlete services and clients configuration to Terraform state. This would allow you to adopt Terraform without manually creating the definition of such resources.

The [general import process](https://www.terraform.io/cli/import) is provided by Terraform and has the constraint of not altering the Terraform script with the config imported. So services and clients definition can be pulled from Authlete API server to local state and from local state you can copy the script from there and alter the Terraform script by yourself.

You can check the video below to check how this process is straight forward.

[![asciicast](https://asciinema.org/a/490283.svg)](https://asciinema.org/a/490283?speed=2)
