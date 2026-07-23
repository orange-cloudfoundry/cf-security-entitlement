module github.com/orange-cloudfoundry/cf-security-entitlement/v2

go 1.26.4

replace github.com/codahale/hdrhistogram => github.com/HdrHistogram/hdrhistogram-go v0.0.0-20210305173142-35c7773a578a

exclude (
	github.com/sabhiram/go-gitignore v0.0.0-20210923224102-525f6e181f06
	github.com/vito/go-interact v1.0.1
	github.com/vito/go-interact v1.0.2
)

require (
	code.cloudfoundry.org/cli/v8 v8.18.4
	github.com/alecthomas/units v0.0.0-20240927000941-0f3dac36c52b // indirect
	github.com/cloudfoundry-community/gautocloud v1.9.0
	github.com/cloudfoundry-community/go-cfenv v1.18.0 // indirect
	github.com/denisenkom/go-mssqldb v0.12.3 // indirect
	github.com/go-sql-driver/mysql v1.10.0 // indirect
	github.com/golang/mock v1.6.0 // indirect
	github.com/jessevdk/go-flags v1.6.1
	github.com/jinzhu/gorm v1.9.16
	github.com/lib/pq v1.12.3 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible
	github.com/mattn/go-colorable v0.1.15
	github.com/mattn/go-isatty v0.0.23
	github.com/mattn/go-sqlite3 v1.14.47 // indirect
	github.com/olekukonko/tablewriter v1.1.4
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.70.1
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/sirupsen/logrus v1.9.4
	github.com/spf13/viper v1.21.0 // indirect
)

require (
	github.com/alecthomas/kingpin/v2 v2.4.0
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/gorilla/context v1.1.2
	github.com/gorilla/mux v1.8.1
	github.com/prometheus/client_golang v1.24.0
)

require (
	code.cloudfoundry.org/bytefmt v0.78.0 // indirect
	code.cloudfoundry.org/cli-plugin-repo v0.0.0-20220208212925-633e698c93c0 // indirect
	code.cloudfoundry.org/clock v1.76.0 // indirect
	code.cloudfoundry.org/go-log-cache/v2 v2.0.7 // indirect
	code.cloudfoundry.org/go-loggregator/v9 v9.2.1 // indirect
	code.cloudfoundry.org/jsonry v1.1.4 // indirect
	code.cloudfoundry.org/tlsconfig v0.60.0 // indirect
	code.cloudfoundry.org/ykk v0.0.0-20170424192843-e4df4ce2fd4d // indirect
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/SermoDigital/jose v0.9.2-0.20161205224733-f6df55f235c2 // indirect
	github.com/azer/snakecase v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/bmatcuk/doublestar v1.3.4 // indirect
	github.com/bmizerany/pat v0.0.0-20210406213842-e4b6760bdd6f // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/cloudfoundry/bosh-cli v6.4.1+incompatible // indirect
	github.com/cloudfoundry/bosh-utils v0.0.624 // indirect
	github.com/cppforlife/go-patch v0.2.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/fxamacker/cbor/v2 v2.9.2 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-viper/encoding/hcl v0.1.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/lunixbochs/vtclean v1.0.0 // indirect
	github.com/mattn/go-runewidth v0.0.24 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.3.0 // indirect
	github.com/olekukonko/ll v0.1.8 // indirect
	github.com/pelletier/go-toml/v2 v2.4.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/sabhiram/go-gitignore v0.0.0-20171017070213-362f9845770f // indirect
	github.com/sagikazarmark/locafero v0.12.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/tedsuo/rata v1.0.1-0.20170830210128-07d200713958 // indirect
	github.com/vito/go-interact v1.0.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xhit/go-str2duration/v2 v2.1.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260622175928-b703f567277d // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260622175928-b703f567277d // indirect
	google.golang.org/grpc v1.82.1 // indirect
	google.golang.org/protobuf v1.36.12-0.20260120151049-f2248ac996af // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.28 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	k8s.io/apimachinery v0.36.2 // indirect
	k8s.io/client-go v0.36.2 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	k8s.io/kube-openapi v0.0.0-20260624041617-8f3fa4921821 // indirect
	k8s.io/utils v0.0.0-20260626114624-be93311217bd // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.4.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)
