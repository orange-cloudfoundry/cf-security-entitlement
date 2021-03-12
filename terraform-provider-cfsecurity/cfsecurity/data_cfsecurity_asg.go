package cfsecurity

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/orange-cloudfoundry/cf-security-entitlement/clients"
)

func dataSourceAsg() *schema.Resource {

	return &schema.Resource{

		Read: dataSourceAsgRead,

		Schema: map[string]*schema.Schema{

			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func dataSourceAsgRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client)
	secGroup, err := client.GetSecGroupByName(d.Get("name").(string))
	if err != nil {
		return err
	}
	d.SetId(secGroup.Guid)
	return nil
}
