package cfsecurity

import (
	"fmt"

	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/orange-cloudfoundry/cf-security-entitlement/clients"
)

func resourceBindAsg() *schema.Resource {

	return &schema.Resource{

		Create: resourceBindAsgCreate,
		Read:   resourceBindAsgRead,
		Update: resourceBindAsgUpdate,
		Delete: resourceBindAsgDelete,
		Importer: &schema.ResourceImporter{
			State: func(d *schema.ResourceData, meta interface{}) ([]*schema.ResourceData, error) {
				return []*schema.ResourceData{d}, nil
			},
		},

		Schema: map[string]*schema.Schema{
			"bind": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Set: func(v interface{}) int {
					elem := v.(map[string]interface{})
					str := fmt.Sprintf("%s-%s",
						elem["asg_id"],
						elem["space_id"],
					)
					return StringHashCode(str)
				},
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"asg_id": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
						"space_id": &schema.Schema{
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"force": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
			},
		},
	}
}

func resourceBindAsgCreate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client)
	id, err := uuid.GenerateUUID()
	if err != nil {
		return err
	}

	for _, elem := range getListOfStructs(d.Get("bind")) {
		err := client.BindSecurityGroup(elem["asg_id"].(string), elem["space_id"].(string))
		if err != nil {
			return err
		}
	}
	d.SetId(id)
	return nil
}

func resourceBindAsgRead(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client)
	secGroups, err := client.ListSecGroups()
	if err != nil {
		return err
	}

	userIsAdmin, _ := client.CurrentUserIsAdmin()
	// check if force and if user is not an admin
	if d.Get("force").(bool) && !userIsAdmin {
		finalBinds := make([]map[string]interface{}, 0)
		for _, secGroup := range secGroups {
			for _, space := range secGroup.SpacesData {
				finalBinds = append(finalBinds, map[string]interface{}{
					"asg_id":   secGroup.Guid,
					"space_id": space.Entity.Guid,
				})
			}
		}
		d.Set("bind", finalBinds)
		return nil
	}

	secGroupsTf := getListOfStructs(d.Get("bind"))
	finalBinds := intersectSlices(secGroupsTf, secGroups, func(source, item interface{}) bool {
		secGroupTf := source.(map[string]interface{})
		secGroup := item.(cfclient.SecGroup)
		asgIDTf := secGroupTf["asg_id"].(string)
		spaceIDTf := secGroupTf["space_id"].(string)
		if asgIDTf != secGroup.Guid {
			return false
		}
		spaces, _ := client.GetSecGroupSpaces(secGroup.Guid)
		return isInSlice(spaces, func(object interface{}) bool {
			space := object.(cfclient.Space)
			return space.Guid == spaceIDTf
		})
	})
	d.Set("bind", finalBinds)
	return nil
}

func resourceBindAsgUpdate(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client)

	old, now := d.GetChange("bind")
	remove, add := getListMapChanges(old, now, func(source, item map[string]interface{}) bool {
		return source["asg_id"] == item["asg_id"] &&
			source["space_id"] == item["space_id"]
	})
	if len(remove) > 0 {
		for _, bind := range remove {
			err := client.UnbindSecurityGroup(bind["asg_id"].(string), bind["space_id"].(string))
			if err != nil && !isNotFoundErr(err) {
				return err
			}
		}

	}
	if len(add) > 0 {
		for _, bind := range add {
			err := client.BindSecurityGroup(bind["asg_id"].(string), bind["space_id"].(string))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceBindAsgDelete(d *schema.ResourceData, meta interface{}) error {
	client := meta.(*clients.Client)
	for _, elem := range getListOfStructs(d.Get("bind")) {
		err := client.UnbindSecurityGroup(elem["asg_id"].(string), elem["space_id"].(string))
		if err != nil && !isNotFoundErr(err) {
			return err
		}
	}
	return nil
}
