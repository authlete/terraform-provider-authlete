package provider

import "github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"

func NotZeroString(d *schema.ResourceData, name string) bool {
	return d.Get(name).(string) != ""
}

func NotZeroArray(d *schema.ResourceData, name string) bool {
	return len(d.Get(name).([]interface{})) != 0
}

func NotZeroNumber(d *schema.ResourceData, name string) bool {
	return d.Get(name).(int) != 0
}
