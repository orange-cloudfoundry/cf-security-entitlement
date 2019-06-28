module github.com/orange-cloudfoundry/cf-security-entitlement

go 1.12

replace github.com/ugorji/go => github.com/ugorji/go v0.0.0-20181204163529-d75b2dcb6bc8

require (
	code.cloudfoundry.org/cli v6.44.1+incompatible
	github.com/cloudfoundry-community/gautocloud v1.1.3
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20190201205600-f136f9222381
	github.com/gorilla/mux v1.7.2 // indirect
	github.com/hashicorp/go-uuid v1.0.1
	github.com/hashicorp/terraform v0.12.0
	github.com/jessevdk/go-flags v1.4.0
	github.com/jinzhu/gorm v1.9.8
	github.com/logrusorgru/aurora v0.0.0-20190428105938-cea283e61946
	github.com/mattn/go-colorable v0.1.2
	github.com/mattn/go-isatty v0.0.8
	github.com/o1egl/gormrus v0.0.0-20190416211302-fde1f6a23457
	github.com/olekukonko/tablewriter v0.0.1
	github.com/orange-cloudfoundry/gobis v1.4.0
	github.com/orange-cloudfoundry/gobis-middlewares v1.3.0
	github.com/pkg/errors v0.8.1
	github.com/sirupsen/logrus v1.4.2
	github.com/thoas/go-funk v0.4.0
)
