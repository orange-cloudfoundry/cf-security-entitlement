package model

import "code.cloudfoundry.org/cli/resources"

type ConfigServer struct {
	LogLevel              string   `cloud:"log_level"`
	LogJSON               *bool    `cloud:"log_json"`
	LogNoColor            bool     `cloud:"log_no_color"`
	FallbackToSqlite      bool     `cloud:"fallback_to_sqlite"`
	SSLCertFile           string   `cloud:"ssl_cert_file" cloud-default:""`
	SSLKeyFile            string   `cloud:"ssl_key_file" cloud-default:""`
	SQLitePath            string   `cloud:"sqlite_path" cloud-default:"sec_entitlement.db"`
	SQLCnxMaxIdle         int      `cloud:"sql_cnx_max_idle" cloud-default:"20"`
	SQLCnxMaxOpen         int      `cloud:"sql_cnx_max_open" cloud-default:"100"`
	SQLCnxMaxLife         string   `cloud:"sql_cnx_max_life" cloud-default:"1h"`
	TrustedCaCertificates []string `cloud:"trusted_ca_certificates"`
	NotExitWhenConnFailed bool     `cloud:"not_exit_when_con_failed"`
	CloudFoundry          CFConfig `cloud:"cloud_foundry"`
	AuthKey               string   `cloud:"auth_key"`
	JWT                   JWT      `cloud:"jwt"`
}

type JWT struct {
	Alg    string `cloud:"alg"`
	Secret string `cloud:"secret"`
}

type CFConfig struct {
	Endpoint          string `cloud:"endpoint"`
	ClientID          string `cloud:"client_id"`
	ClientSecret      string `cloud:"client_secret"`
	SkipSSLValidation bool   `cloud:"skip_ssl_validation"`
	UAAEndpoint       string `cloud:"uaa_endpoint"`
}

type Info struct {
	Links struct {
		// Self is the link to the Cloudfoundry API.
		Self resources.APILink `json:"self"`

		// AppSSH is the link for application ssh info.
		AppSSH resources.APILink `json:"app_ssh"`

		// CCV3 is the link to the Cloud Controller V3 API.
		CCV3 resources.APILink `json:"cloud_controller_v3"`

		// Logging is the link to the Logging API.
		Logging resources.APILink `json:"logging"`

		// Logging is the link to the Logging API.
		LogCache resources.APILink `json:"log_cache"`

		// NetworkPolicyV1 is the link to the Container to Container Networking
		// API.
		NetworkPolicyV1 resources.APILink `json:"network_policy_v1"`

		// Routing is the link to the routing API
		Routing resources.APILink `json:"routing"`

		// UAA is the link to the UAA API.
		UAA resources.APILink `json:"uaa"`

		// Login is the link to the Login API.
		Login resources.APILink `json:"login"`
	}
}
