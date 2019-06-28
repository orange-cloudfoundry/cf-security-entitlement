package main

import (
	"fmt"
	"github.com/cloudfoundry-community/gautocloud"
	_ "github.com/cloudfoundry-community/gautocloud/connectors/databases/gorm"
	"github.com/cloudfoundry-community/gautocloud/connectors/generic"
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/o1egl/gormrus"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/casbin"
	"github.com/orange-cloudfoundry/gobis-middlewares/ceftrace"
	"github.com/orange-cloudfoundry/gobis-middlewares/jwt"
	"github.com/orange-cloudfoundry/gobis-middlewares/trace"
	log "github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

func init() {
	if gautocloud.IsInACloudEnv() && gautocloud.CurrentCloudEnv().Name() != "localcloud" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	gautocloud.RegisterConnector(generic.NewConfigGenericConnector(model.ConfigServer{}))

}

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	panic(boot())
}

var client *cfclient.Client
var DB *gorm.DB

func retrieveGormDb(config model.ConfigServer) *gorm.DB {
	var db *gorm.DB
	err := gautocloud.Inject(&db)
	if err == nil {
		if config.SQLCnxMaxOpen != 0 {
			db.DB().SetMaxOpenConns(config.SQLCnxMaxOpen)
		}
		if config.SQLCnxMaxIdle != 0 {
			db.DB().SetMaxOpenConns(config.SQLCnxMaxIdle)
		}
		if config.SQLCnxMaxLife != "" {
			duration, err := time.ParseDuration(config.SQLCnxMaxLife)
			if err != nil {
				log.Warnf("Invalid configuration for SQLCnxMaxLife : %s", err.Error())
			} else {
				db.DB().SetConnMaxLifetime(duration)
			}
		}
		return db
	}
	if !config.FallbackToSqlite {
		log.Fatalf("Error when loading database: %s", err.Error())
	}
	log.Warnf("Error when loading database, switching to sqlite, see message: %s", err.Error())
	db, _ = gorm.Open("sqlite3", config.SQLitePath)
	return db
}

func boot() error {
	var config model.ConfigServer
	gautocloud.Inject(&config)

	loadLogConfig(config)
	err := loadClient(config)
	if err != nil {
		return err
	}
	DB = retrieveGormDb(config)
	defer DB.Close()

	DB.SetLogger(gormrus.New())
	if log.GetLevel() == log.DebugLevel {
		DB.LogMode(true)
	}
	DB.AutoMigrate(&model.EntitlementSecGroup{})

	info, err := client.GetInfo()
	if err != nil {
		return err
	}

	jwtConfig := jwt.JwtConfig{
		Jwt: &jwt.JwtOptions{
			Enabled: true,
			Issuer:  info.TokenEndpoint + "/oauth/token",
			Alg:     config.JWT.Alg,
			Secret:  config.JWT.Secret,
		},
	}
	casbinConfig := casbin.CasbinConfig{
		Casbin: &casbin.CasbinOption{
			Enabled: true,
			Policies: []casbin.CasbinPolicy{
				{
					Type: "p",
					Sub:  "cloud_controller.admin",
					Obj:  "*",
					Act:  "*",
				},
			},
		},
	}
	traceConfig := trace.TraceConfig{
		Trace: &trace.TraceOptions{
			Enabled: true,
		},
	}
	bindingConfig := SecGroupConfig{
		Binding: &SecGroupOptions{
			Enabled: true,
		},
	}
	cefConfig := ceftrace.CefTraceConfig{
		CefTrace: &ceftrace.CefTraceOptions{
			Enabled:       true,
			DeviceVendor:  "Orange",
			DeviceProduct: "cf-security-entitlement",
			DeviceVersion: version,
		},
	}
	builder := gobis.Builder()
	builder = builder.
		AddRouteHandler("/v2/security_entitlement", http.HandlerFunc(handleEntitleSecGroup)).
		WithMethods("POST").
		WithMiddlewareParams(jwtConfig, casbinConfig, traceConfig, cefConfig).
		AddRouteHandler("/v2/security_entitlement", http.HandlerFunc(handleRevokeSecGroup)).
		WithMethods("DELETE").
		WithMiddlewareParams(jwtConfig, casbinConfig, traceConfig, cefConfig).
		AddRouteHandler("/v2/security_entitlement", http.HandlerFunc(handleListSecGroup)).
		WithMethods("GET").
		WithMiddlewareParams(jwtConfig, casbinConfig, traceConfig, cefConfig).
		AddRoute("/v2/security_groups/**", config.CloudFoundry.Endpoint+"/v2/security_groups").
		WithMethods("PUT", "DELETE", "GET").
		WithMiddlewareParams(jwtConfig, bindingConfig, traceConfig, cefConfig)
	if config.CloudFoundry.SkipSSLValidation {
		builder = builder.WithInsecureSkipVerify()
	}
	routes := builder.Build()
	r, err := gobis.NewHandler(routes,
		jwt.NewJwt(),
		casbin.NewCasbin(),
		ceftrace.NewCefTrace(),
		trace.NewTrace(),
		&SecGroupMiddleware{},
	)
	if err != nil {
		panic(err)
	}
	if !config.NotExitWhenConnFailed {
		go checkDbConnection(DB)
	}

	port := gautocloud.GetAppInfo().Port
	if port == 0 {
		port = 8091
	}
	if (config.SSLCertFile != "") && (config.SSLKeyFile != "") {
		log.Infof("serving https on %s", fmt.Sprintf(":%d", port))
		return http.ListenAndServeTLS(fmt.Sprintf(":%d", port), config.SSLCertFile, config.SSLKeyFile, r)
	}
	log.Infof("serving http on %s", fmt.Sprintf(":%d", port))
	return http.ListenAndServe(fmt.Sprintf(":%d", port), r)
}

func checkDbConnection(db *gorm.DB) {
	for {
		err := db.DB().Ping()
		if err != nil {
			db.Close()
			log.Fatalf("Error when pinging database: %s", err.Error())
		}
		time.Sleep(5 * time.Minute)
	}
}

func loadClient(c model.ConfigServer) error {
	var err error
	configClient := &cfclient.Config{
		ApiAddress:        c.CloudFoundry.Endpoint,
		ClientID:          c.CloudFoundry.ClientID,
		ClientSecret:      c.CloudFoundry.ClientSecret,
		SkipSslValidation: c.CloudFoundry.SkipSSLValidation,
	}
	client, err = cfclient.NewClient(configClient)
	if err != nil {
		return err
	}
	return nil
}

func loadLogConfig(c model.ConfigServer) {
	if c.LogJSON != nil {
		if *c.LogJSON {
			log.SetFormatter(&log.JSONFormatter{})
		} else {
			log.SetFormatter(&log.TextFormatter{
				DisableColors: c.LogNoColor,
			})
		}
	}

	if c.LogLevel == "" {
		return
	}
	switch strings.ToUpper(c.LogLevel) {
	case "ERROR":
		log.SetLevel(log.ErrorLevel)
		return
	case "WARN":
		log.SetLevel(log.WarnLevel)
		return
	case "DEBUG":
		log.SetLevel(log.DebugLevel)
		return
	case "PANIC":
		log.SetLevel(log.PanicLevel)
		return
	case "FATAL":
		log.SetLevel(log.FatalLevel)
		return
	}
}
