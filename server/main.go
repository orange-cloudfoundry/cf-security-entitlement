package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"code.cloudfoundry.org/cli/api/cloudcontroller/ccv3"
	ccWrapper "code.cloudfoundry.org/cli/api/cloudcontroller/wrapper"
	"code.cloudfoundry.org/cli/api/uaa"
	"code.cloudfoundry.org/cli/util/configv3"
	"github.com/alecthomas/kingpin/v2"
	"github.com/cloudfoundry-community/gautocloud"
	_ "github.com/cloudfoundry-community/gautocloud/connectors/databases/gorm"
	"github.com/cloudfoundry-community/gautocloud/connectors/generic"
	"github.com/gorilla/mux"

	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/orange-cloudfoundry/cf-security-entitlement/client"
	"github.com/orange-cloudfoundry/cf-security-entitlement/model"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	log "github.com/sirupsen/logrus"
)

type OauthToken struct {
	AccessToken string `json:"access_token,omitempty"`
	TokenType   string `json:"token_type,omitempty"`
	Expires     int    `json:"expires_in,omitempty"`
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

	r := mux.NewRouter()
	auth := NewAuth(&config.JWT)
	r.Use(auth.authHandler)
	r.Use(logHandler)
	r.Use(metricHandler)

	r.HandleFunc("/v2/security_entitlement", handleEntitleSecGroup).Methods("POST")
	r.HandleFunc("/v2/security_entitlement", handleRevokeSecGroup).Methods("DELETE")
	r.HandleFunc("/v2/security_entitlement", handleListSecGroup).Methods("GET")
	r.PathPrefix("/v3/security_groups").HandlerFunc(secGoupsHandler).Methods("GET", "POST", "DELETE")
	r.HandleFunc("/v3/bindings", handleBindSecGroup).Methods("POST", "DELETE")
	r.Handle("/metrics", promhttp.Handler())

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

	cfclient = client.NewClient(c.CloudFoundry.Endpoint, ccClientV3, accessToken, info.Links.Self.HREF, tr)
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

	cfClient := &http.Client{Transport: tr}
	info := model.Info{}
	req, err := http.NewRequest(http.MethodGet, Endpoint, nil)
	if err != nil {
		return info, err
	}

	resp, err := cfClient.Do(req)
	if err != nil {
		return info, err
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return info, err
	}

	if err = json.Unmarshal(body, &info); err != nil {
		return info, errors.Wrap(err, "Error unmarshalling Info")
	}
	json.Unmarshal(body, &info)

	return info, nil
}

func AuthenticateWithExpire(endpoint string, clientId string, clientSecret string, tr *http.Transport) (string, time.Time, error) {
	body := fmt.Sprint("grant_type=client_credentials")
	var jsonData = []byte(body)
	accessTokens := OauthToken{}
	cfClient := &http.Client{Transport: tr}
	Request, err := http.NewRequest(http.MethodPost, endpoint+"/oauth/token", bytes.NewBuffer(jsonData))
	if err != nil {
		return "", time.Now(), err
	}
	Request.SetBasicAuth(clientId, clientSecret)
	Request.Header.Add("Content-type", "application/x-www-form-urlencoded")
	Request.Header.Add("Accept", "application/json")

	resp, err := cfClient.Do(Request)
	if err != nil {
		return "", time.Now(), err
	}
	defer resp.Body.Close()
	buf, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Now(), err
	}
	if err = json.Unmarshal(buf, &accessTokens); err != nil {
		return "", time.Now(), errors.Wrap(err, "Error unmarshalling Auth")
	}

	accessToken := fmt.Sprintf("bearer %s", accessTokens.AccessToken)

	expiresIn := time.Duration(accessTokens.Expires) * time.Second
	expires := time.Now().Add(expiresIn)

	// Taking 10 minute off the timer to have a margin of error
	expiresAt = expires.Add(time.Duration(-10) * time.Minute)

	return accessToken, expiresAt, err
}
