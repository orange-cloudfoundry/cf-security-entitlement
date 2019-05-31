package model

type EntitlementSecGroup struct {
	SecurityGroupGUID string `gorm:"primary_key" json:"security_group_guid"`
	OrganizationGUID  string `gorm:"primary_key" json:"organization_guid"`
}
