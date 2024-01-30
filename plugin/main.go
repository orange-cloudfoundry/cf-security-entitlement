package main

import (
	"net/url"
	"strconv"
	"strings"

	"code.cloudfoundry.org/cli/plugin"
	"github.com/jessevdk/go-flags"
	"github.com/orange-cloudfoundry/cf-security-entitlement/plugin/messages"
	"github.com/prometheus/common/version"
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
		Name:    "cf-security-entitlement",
		Version: getVersion(),
		Commands: []plugin.Command{
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
				HelpText: "List all security groups available for an org manager, silent mode show only security group names",
				UsageDetails: plugin.Usage{
					Usage: "manager-security-groups  [-s|--silent]",
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

func getVersion() plugin.VersionType {
	major, minor, build := 0, 0, 0
	versions := strings.Split(version.Version, ".")

	if len(versions) == 3 {
		major, _ = strconv.Atoi(versions[0])
		minor, _ = strconv.Atoi(versions[1])
		build, _ = strconv.Atoi(versions[2])
	}

	return plugin.VersionType{
		Major: major,
		Minor: minor,
		Build: build,
	}
}

func main() {
	plugin.Start(&SecurityPlugin{})
}
