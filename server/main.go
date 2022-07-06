package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	ccWrapper "code.cloudfoundry.org/cli/api/cloudcontroller/wrapper"
	"code.cloudfoundry.org/cli/api/uaa"
	"code.cloudfoundry.org/cli/util/configv3"
	"github.com/cloudfoundry-community/gautocloud"
	_ "github.com/cloudfoundry-community/gautocloud/connectors/databases/gorm"
	"github.com/cloudfoundry-community/gautocloud/connectors/generic"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/o1egl/gormrus"
	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"
	"github.com/orange-cloudfoundry/gobis"
	"github.com/orange-cloudfoundry/gobis-middlewares/casbin"
	"github.com/orange-cloudfoundry/gobis-middlewares/ceftrace"
	"github.com/orange-cloudfoundry/gobis-middlewares/jwt"
	"github.com/orange-cloudfoundry/gobis-middlewares/trace"
	"github.com/pkg/errors"
	"github.com/prometheus/common/version"
	log "github.com/sirupsen/logrus"
	"gopkg.in/alecthomas/kingpin.v2"
)

type OauthToken struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Exprires    int    `json:"expires_in,omitempty"`
	Jti         string `json:"jti,omitempty"`
}

func init() {
	if gautocloud.IsInACloudEnv() && gautocloud.CurrentCloudEnv().Name() != "localcloud" {
		log.SetFormatter(&log.JSONFormatter{})
	}
	gautocloud.RegisterConnector(generic.NewConfigGenericConnector(model.ConfigServer{}))

}

func main() {
	panic(boot())
}

var expiresAt time.Time
var cfclient *client.Client
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
	kingpin.Version(version.Print("cfsecurity-server"))
	kingpin.HelpFlag.Short('h')
	usage := strings.ReplaceAll(kingpin.DefaultUsageTemplate, "usage: ", "usage: CLOUD_FILE=config.yml ")
	kingpin.UsageTemplate(usage)
	kingpin.Parse()

	var config model.ConfigServer
	err := gautocloud.Inject(&config)
	if err != nil {
		return err
	}
	loadLogConfig(config)
	err = loadClient(shallowDefaultTransport(config.TrustedCaCertificates, config.CloudFoundry.SkipSSLValidation), config)
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
	info, err := GetInfo(config.CloudFoundry.Endpoint, config.CloudFoundry.SkipSSLValidation, config.TrustedCaCertificates)
	if err != nil {
		return err
	}

	jwtConfig := jwt.JwtConfig{
		Jwt: &jwt.JwtOptions{
			Enabled: true,
			Issuer:  info.Links.UAA.HREF + "/oauth/token",
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
			DeviceVersion: version.Version,
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
		AddRoute("/v3/security_groups/**", config.CloudFoundry.Endpoint+"/v3/security_groups").
		WithMethods("POST", "DELETE", "GET").
		WithMiddlewareParams(jwtConfig, bindingConfig, traceConfig, cefConfig)

	routes := builder.Build()
	factory := gobis.NewRouterFactory(
		jwt.NewJwt(),
		casbin.NewCasbin(),
		ceftrace.NewCefTrace(),
		trace.NewTrace(),
		&SecGroupMiddleware{},
	)
	factory.(*gobis.RouterFactoryService).CreateTransportFunc = func(proxyRoute gobis.ProxyRoute) http.RoundTripper {
		return gobis.NewRouteTransportWithHttpTransport(
			proxyRoute,
			shallowDefaultTransport(config.TrustedCaCertificates, config.CloudFoundry.SkipSSLValidation),
		)
	}
	r, err := gobis.NewHandlerWithFactory(routes, factory)
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

func loadClient(transport *http.Transport, c model.ConfigServer) error {
	var err error
	httpClient := &http.Client{
		Transport: transport,
	}

	if c.CloudFoundry.UAAEndpoint != "" {
		roundTripper, err := loadTranslatedTransportUaa(httpClient, transport, c)
		if err != nil {
			return err
		}
		httpClient.Transport = roundTripper
	}
	config := &configv3.Config{
		ConfigFile: configv3.JSONConfig{
			ConfigVersion:        3,
			UAAEndpoint:          c.CloudFoundry.Endpoint,
			UAAOAuthClient:       c.CloudFoundry.ClientID,
			UAAOAuthClientSecret: c.CloudFoundry.ClientSecret,
			SkipSSLValidation:    c.CloudFoundry.SkipSSLValidation,
			Target:               c.CloudFoundry.Endpoint,
		},
	}
	uaaClient := uaa.NewClient(config)
	authWrapperV3 := ccWrapper.NewUAAAuthentication(uaaClient, config)
	ccWrappersV3 := []ccv3.ConnectionWrapper{
		authWrapperV3,
		ccWrapper.NewRetryRequest(config.RequestRetryCount()),
	}

	ccClientV3 := ccv3.NewClient(ccv3.Config{
		AppName:            config.BinaryName(),
		AppVersion:         config.BinaryVersion(),
		JobPollingTimeout:  config.OverallPollingTimeout(),
		JobPollingInterval: config.PollingInterval(),
		Wrappers:           ccWrappersV3,
	})

	ccClientV3.TargetCF(ccv3.TargetSettings{
		URL:               config.Target(),
		SkipSSLValidation: config.SkipSSLValidation(),
		DialTimeout:       config.DialTimeout(),
	})

	info, err := GetInfo(c.CloudFoundry.Endpoint, c.CloudFoundry.SkipSSLValidation, c.TrustedCaCertificates)
	if err != nil {
		return err
	}

	err = uaaClient.SetupResources(info.Links.UAA.HREF, info.Links.Login.HREF)
	if err != nil {
		return fmt.Errorf("Error setup resource uaa: %s", err)
	}
	tr := shallowDefaultTransport(c.TrustedCaCertificates, c.CloudFoundry.SkipSSLValidation)

	accessToken, _, err := AuthenticateWithExpire(c.CloudFoundry.UAAEndpoint, config.UAAOAuthClient(), config.UAAOAuthClientSecret(), tr)
	if err != nil {
		return fmt.Errorf("Error when authenticate on cf: %s", err)
	}
	if accessToken == "" {
		return fmt.Errorf("A pair of username/password or a pair of client_id/client_secret muste be set.")
	}

	cfclient = client.NewClient(c.CloudFoundry.Endpoint, ccClientV3, accessToken, info.Links.Self.HREF, *tr)
	if err != nil {
		return err
	}

	return nil
}

func loadTranslatedTransportUaa(httpClient *http.Client, transport *http.Transport, c model.ConfigServer) (http.RoundTripper, error) {
	var roundTripper http.RoundTripper
	roundTripper = transport
	resp, err := GetInfo(c.CloudFoundry.Endpoint, c.CloudFoundry.SkipSSLValidation, c.TrustedCaCertificates)
	if err != nil {
		return nil, err
	}
	if resp.Links.Login.HREF != "" {
		roundTripper = NewTranslateTransport(roundTripper, resp.Links.Login.HREF, c.CloudFoundry.UAAEndpoint)
	}
	if resp.Links.UAA.HREF != "" {
		roundTripper = NewTranslateTransport(roundTripper, resp.Links.UAA.HREF, c.CloudFoundry.UAAEndpoint)
	}
	return roundTripper, nil
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

func shallowDefaultTransport(certs []string, skipVerify bool) *http.Transport {
	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	for i, certs := range certs {
		ok := rootCAs.AppendCertsFromPEM([]byte(certs))
		if !ok {
			log.Warnf("Cannot append trusted ca certificates at %d", i)
		}
	}
	defaultTransport := http.DefaultTransport.(*http.Transport)
	return &http.Transport{
		Proxy:                 defaultTransport.Proxy,
		TLSHandshakeTimeout:   defaultTransport.TLSHandshakeTimeout,
		ExpectContinueTimeout: defaultTransport.ExpectContinueTimeout,
		TLSClientConfig: &tls.Config{
			RootCAs:            rootCAs,
			InsecureSkipVerify: skipVerify,
		},
	}
}

func GetInfo(Endpoint string, SkipVerify bool, certs []string) (model.Info, error) {
	tr := shallowDefaultTransport(certs, SkipVerify)

	client := &http.Client{Transport: tr}
	info := model.Info{}
	req, err := http.NewRequest(http.MethodGet, Endpoint, nil)
	if err != nil {
		return info, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}

	if err = json.Unmarshal(body, &info); err != nil {
		return info, errors.Wrap(err, "Error unmarshaling Info")
	}
	json.Unmarshal(body, &info)

	return info, nil
}

func AuthenticateWithExpire(endpoint string, clientId string, clientSecret string, tr *http.Transport) (string, time.Time, error) {
	body := fmt.Sprint("grant_type=client_credentials")
	var jsonData = []byte(body)
	accessTokens := OauthToken{}
	client := &http.Client{Transport: tr}
	Request, err := http.NewRequest(http.MethodPost, endpoint+"/oauth/token", bytes.NewBuffer(jsonData))
	Request.SetBasicAuth(clientId, clientSecret)
	Request.Header.Add("Content-type", "application/x-www-form-urlencoded")
	Request.Header.Add("Accept", "application/json")

	resp, err := client.Do(Request)
	if err != nil {
		return "", time.Now(), err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Now(), err
	}
	if err = json.Unmarshal(buf, &accessTokens); err != nil {
		return "", time.Now(), errors.Wrap(err, "Error unmarshaling Auth")
	}

	accessToken := fmt.Sprintf("bearer %s", accessTokens.AccessToken)

	expiresIn := time.Duration(accessTokens.Exprires) * time.Second
	expiresAt = time.Now().Add(expiresIn)

	return accessToken, expiresAt, err

}
