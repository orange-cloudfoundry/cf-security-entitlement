module github.com/orange-cloudfoundry/cf-security-entitlement

go 1.15

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.0.0-20210305173142-35c7773a578a

require (
	code.cloudfoundry.org/cli v7.1.0+incompatible
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/cloudfoundry-community/gautocloud v1.1.6
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20210621174645-7773f7e22665
	github.com/cloudfoundry-community/go-cfenv v1.18.0 // indirect
	github.com/denisenkom/go-mssqldb v0.10.0 // indirect
	github.com/go-sql-driver/mysql v1.6.0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/jessevdk/go-flags v1.5.0
	github.com/jinzhu/gorm v1.9.16
	github.com/lib/pq v1.10.2 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mattn/go-colorable v0.1.8
	github.com/mattn/go-isatty v0.0.13
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mattn/go-sqlite3 v1.14.7 // indirect
	github.com/o1egl/gormrus v0.0.0-20190416211302-fde1f6a23457
	github.com/olekukonko/tablewriter v0.0.5
	github.com/orange-cloudfoundry/gobis v1.4.3
	github.com/orange-cloudfoundry/gobis-middlewares v1.3.3
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.29.0
	github.com/prometheus/procfs v0.7.0 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/viper v1.8.1 // indirect
	github.com/thoas/go-funk v0.9.0
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)
