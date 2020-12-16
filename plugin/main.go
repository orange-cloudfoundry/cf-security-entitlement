package main

import (
	"net/url"
	"strings"

	"code.cloudfoundry.org/cli/plugin"
	"github.com/jessevdk/go-flags"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
)

type Options struct {
}

var options Options
var parser = flags.NewParser(&options, flags.HelpFlag|flags.PassDoubleDash|flags.IgnoreUnknown)
var cliConnection plugin.CliConnection
var defaultEndpoint string

func Parse(args []string) error {

	_, err := parser.ParseArgs(args)
	if err != nil {
		if errFlag, ok := err.(*flags.Error); ok && errFlag.Type == flags.ErrCommandRequired {
			return nil
		}
		if errFlag, ok := err.(*flags.Error); ok && errFlag.Type == flags.ErrHelp {
			messages.Println(err.Error())
			return nil
		}
		return err
	}

	return nil
}

type SecurityPlugin struct{}

func (p *SecurityPlugin) GetMetadata() plugin.PluginMetadata {
	return plugin.PluginMetadata{
		Name: "cf-security-entitlement",
		Version: plugin.VersionType{
			Major: 1,
			Minor: 0,
			Build: 1,
		},
		Commands: []plugin.Command{
			{
				Name:     "enable-security-group",
				HelpText: "Entitle an organization to a security group",
				UsageDetails: plugin.Usage{
					Usage: "enable-security-group SECURITY-GROUP ORG",
				},
			},
			{
				Name:     "disable-security-group",
				HelpText: "Revoke an organization to a security group",
				UsageDetails: plugin.Usage{
					Usage: "disable-security-group SECURITY-GROUP ORG",
				},
			},
			{
				Name:     "entitlement-security-groups",
				HelpText: "List current security groups entitlements",
				UsageDetails: plugin.Usage{
					Usage: "entitlement-security-groups",
				},
			},
			{
				Name:     "bind-manager-security-group",
				HelpText: "Bind a security group to a particular space, or all existing spaces of an org by an org manager",
				UsageDetails: plugin.Usage{
					Usage: "bind-manager-security-group SECURITY_GROUP ORG [SPACE]",
				},
			},
			{
				Name:     "unbind-manager-security-group",
				HelpText: "Unbind a security group to a particular space, or all existing spaces of an org by an org manager",
				UsageDetails: plugin.Usage{
					Usage: "unbind-manager-security-group SECURITY_GROUP ORG [SPACE]",
				},
			},
			{
				Name:     "manager-security-groups",
				HelpText: "List all security groups available for an org manager",
				UsageDetails: plugin.Usage{
					Usage: "manager-security-groups",
				},
			},
			{
				Name:     "manager-security-group",
				HelpText: "Show a single security group available for an org manager",
				UsageDetails: plugin.Usage{
					Usage: "manager-security-group NAME",
				},
			},
		},
	}
}

func (p *SecurityPlugin) Run(cc plugin.CliConnection, args []string) {
	cliConnection = cc
	action := args[0]
	if action == "CLI-MESSAGE-UNINSTALL" {
		return
	}

	apiUrl, err := cc.ApiEndpoint()
	if err != nil {
		messages.Error(err.Error())
		return
	}
	uri, err := url.Parse(apiUrl)
	if err != nil {
		messages.Error(err.Error())
		return
	}
	pHost := strings.SplitN(uri.Host, ".", 2)
	pHost[0] = "cfsecurity"
	uri.Host = strings.Join(pHost, ".")
	uri.Path = ""

	defaultEndpoint = uri.String()

	err = Parse(args)
	if err != nil {
		messages.Fatal(err.Error())
	}
}

func main() {
	plugin.Start(&SecurityPlugin{})
}
