package cfsecurity

import (
	"github.com/cloudfoundry-community/go-cfclient"
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/orange-cloudfoundry/cf-security-entitlement/clients"
	"net/url"
	"strings"
)

// Provider -
func Provider() terraform.ResourceProvider {

	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"cf_api_url": &schema.Schema{
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("CF_API_URL", ""),
			},
			"cf_security_url": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("CF_SECURITY_URL", ""),
			},
			"user": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("CF_USER", "admin"),
			},
			"password": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("CF_PASSWORD", ""),
			},
			"cf_client_id": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("CF_CLIENT_ID", ""),
			},
			"cf_client_secret": &schema.Schema{
				Type:        schema.TypeString,
				Optional:    true,
				DefaultFunc: schema.EnvDefaultFunc("CF_CLIENT_SECRET", ""),
			},
			"skip_ssl_validation": &schema.Schema{
				Type:        schema.TypeBool,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("CF_SKIP_SSL_VALIDATION", false),
			},
		},

		DataSourcesMap: map[string]*schema.Resource{
			"cfsecurity_asg": dataSourceAsg(),
		},

		ResourcesMap: map[string]*schema.Resource{
			"cfsecurity_bind_asg":    resourceBindAsg(),
			"cfsecurity_entitle_asg": resourceEntitleAsg(),
		},

		ConfigureFunc: providerConfigure,
	}
}

func providerConfigure(d *schema.ResourceData) (interface{}, error) {
	config := &cfclient.Config{
		ApiAddress:        d.Get("cf_api_url").(string),
		Username:          d.Get("user").(string),
		Password:          d.Get("password").(string),
		ClientID:          d.Get("cf_client_id").(string),
		ClientSecret:      d.Get("cf_client_secret").(string),
		SkipSslValidation: d.Get("skip_ssl_validation").(bool),
	}
	cfClient, err := cfclient.NewClient(config)
	if err != nil {
		return nil, err
	}
	uri, err := url.Parse(d.Get("cf_api_url").(string))
	if err != nil {
		return nil, err
	}
	pHost := strings.SplitN(uri.Host, ".", 2)
	pHost[0] = "cfsecurity"
	uri.Host = strings.Join(pHost, ".")
	uri.Path = ""

	securityEndpoint := uri.String()
	if tmpSecEndpoint, ok := d.GetOk("cf_security_url"); ok {
		securityEndpoint = tmpSecEndpoint.(string)
	}

	return clients.NewClient(securityEndpoint, cfClient), nil
}
