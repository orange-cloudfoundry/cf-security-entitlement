module github.com/orange-cloudfoundry/cf-security-entitlement

go 1.21

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.0.0-20210305173142-35c7773a578a

require (
	code.cloudfoundry.org/cli v0.0.0-20210824215059-5ffa262bb2e5
	github.com/alecthomas/units v0.0.0-20211218093645-b94a6e3cc137 // indirect
	github.com/cloudfoundry-community/gautocloud v1.3.1
	github.com/cloudfoundry-community/go-cfenv v1.18.0 // indirect
	github.com/denisenkom/go-mssqldb v0.12.3 // indirect
	github.com/go-sql-driver/mysql v1.7.1 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/jessevdk/go-flags v1.5.0
	github.com/jinzhu/gorm v1.9.16
	github.com/lib/pq v1.10.9 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mattn/go-colorable v0.1.13
	github.com/mattn/go-isatty v0.0.19
	github.com/mattn/go-sqlite3 v1.14.17 // indirect
	github.com/o1egl/gormrus v0.0.0-20190416211302-fde1f6a23457
	github.com/olekukonko/tablewriter v0.0.5
	github.com/orange-cloudfoundry/gobis v1.27.0
	github.com/orange-cloudfoundry/gobis-middlewares v1.52.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.44.0
	github.com/prometheus/procfs v0.11.1 // indirect
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/viper v1.16.0 // indirect
	github.com/thoas/go-funk v0.9.3
)

require (
	code.cloudfoundry.org/jsonry v1.1.4
	github.com/alecthomas/kingpin/v2 v2.3.2
)

require (
	code.cloudfoundry.org/bytefmt v0.0.0-20230612151507-41ef4d1f67a4 // indirect
	code.cloudfoundry.org/cli-plugin-repo v0.0.0-20220208212925-633e698c93c0 // indirect
	code.cloudfoundry.org/rfc5424 v0.0.0-20201103192249-000122071b78 // indirect
	code.cloudfoundry.org/tlsconfig v0.0.0-20230612153104-23c0622de227 // indirect
	github.com/ArthurHlt/logrus-cef-formatter v1.0.0 // indirect
	github.com/Knetic/govaluate v3.0.1-0.20171022003610-9aa49832a739+incompatible // indirect
	github.com/SermoDigital/jose v0.9.2-0.20161205224733-f6df55f235c2 // indirect
	github.com/auth0/go-jwt-middleware v1.0.1 // indirect
	github.com/azer/snakecase v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver v3.5.1+incompatible // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/casbin/casbin v1.9.1 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/charlievieth/fs v0.0.3 // indirect
	github.com/cloudfoundry/bosh-cli v6.4.1+incompatible // indirect
	github.com/cloudfoundry/bosh-utils v0.0.394 // indirect
	github.com/cppforlife/go-patch v0.2.0 // indirect
	github.com/cyphar/filepath-securejoin v0.2.4 // indirect
	github.com/dgrijalva/jwt-go v3.2.0+incompatible // indirect
	github.com/form3tech-oss/jwt-go v3.2.5+incompatible // indirect
	github.com/fsnotify/fsnotify v1.6.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/gorilla/mux v1.8.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/gravitational/trace v1.3.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/mailgun/multibuf v0.2.0 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.4 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/prometheus/client_golang v1.16.0 // indirect
	github.com/prometheus/client_model v0.4.0 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06 // indirect
	github.com/satori/go.uuid v1.2.0 // indirect
	github.com/spf13/afero v1.9.5 // indirect
	github.com/spf13/cast v1.5.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/vulcand/oxy v1.4.2 // indirect
	github.com/vulcand/predicate v1.2.0 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/term v0.13.0 // indirect
	golang.org/x/text v0.13.0 // indirect
	google.golang.org/protobuf v1.31.0 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
