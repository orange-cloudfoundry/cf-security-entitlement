module github.com/orange-cloudfoundry/cf-security-entitlement

go 1.15

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.0.0-20210305173142-35c7773a578a

require (
	code.cloudfoundry.org/cli v7.1.0+incompatible
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/alecthomas/units v0.0.0-20210927113745-59d0afb8317a // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/cloudfoundry-community/gautocloud v1.1.7
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20210823134051-721f0e559306
	github.com/denisenkom/go-mssqldb v0.11.0 // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/jessevdk/go-flags v1.5.0
	github.com/jinzhu/gorm v1.9.16
	github.com/lib/pq v1.10.3 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mattn/go-colorable v0.1.11
	github.com/mattn/go-isatty v0.0.14
	github.com/mattn/go-runewidth v0.0.13 // indirect
	github.com/mattn/go-sqlite3 v1.14.8 // indirect
	github.com/o1egl/gormrus v0.0.0-20190416211302-fde1f6a23457
	github.com/olekukonko/tablewriter v0.0.5
	github.com/orange-cloudfoundry/gobis v1.4.3
	github.com/orange-cloudfoundry/gobis-middlewares v1.3.3
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.31.1
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/sirupsen/logrus v1.8.1
	github.com/spf13/viper v1.9.0 // indirect
	github.com/thoas/go-funk v0.9.1
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210929193557-e81a3d93ecf6 // indirect
	golang.org/x/sys v0.0.0-20210930212924-f542c8878de8 // indirect
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 // indirect
	golang.org/x/text v0.3.7 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)
