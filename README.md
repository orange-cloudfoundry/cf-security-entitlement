# cf-security-entitlement

Add an entitlement mechanism similar to [isolation segment](https://docs.cloudfoundry.org/adminguide/isolation-segments.html#relationships) on Cloud Foundry.

This is providing entitlement on security group which permit to a cloud foundry admin to authorize an org manager to place 
security groups (previously allowed by an admin) himself on space.

This project has 3 parts:
- **server**: api which enable entitlement and security groups placement for org manager. 
**Must be deployed beside cc api through the bosh release https://github.com/orange-cloudfoundry/cf-security-entitlement-boshrelease**
- **cli plugin**: A Cloud Foundry cli plugin which add commands for this api
- **terraform provider**: A [terraform](http://terraform.io/) provider which use api to entitle security groups and which 
can be combined with [cloud foundry provider](https://github.com/cloudfoundry-community/terraform-provider-cf)

## Server

**Please use boshrelease associated for deployment instruction https://github.com/orange-cloudfoundry/cf-security-entitlement-boshrelease**

### Api

#### CRUD Security_groups

Please see doc from cloud foundry http://apidocs.cloudfoundry.org/9.3.0/#security-groups .
Server only check if user is an authorized org manager before transmitting the request to cc api.

#### POST /v2/security_entitlement

**Parameters**:
- `organization_guid`: an organisation guid
- `security_group_guid`: a security group to be enabled on the org

**Headers**:

```
Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y
Host: example.org
Content-Type: application/json
Cookie: 
```

**Curl**:

```
curl "https://cfsecurity.[your-domain.com]/v2/security_entitlement -d '{
  "security_group_guid": "dcee7d89-149b-4bab-9eb9-1e5e73c22aae",
  "organization_guid": "7e0477b9-fff8-41b1-8fd8-969095ba62e5"
}' -X POST \
	-H "Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y" \
	-H "Host: example.org" \
	-H "Content-Type: application/json" \
	-H "Cookie: "
```

**Response status**:
```
201 Created
```

#### GET /v2/security_entitlement

**Parameters**:
- `organization_guid`: an organisation guid
- `security_group_guid`: a security group to be enabled on the org

**Headers**:

```
Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y
Host: example.org
Content-Type: application/json
Cookie: 
```

**Curl**:

```
curl "https://cfsecurity.[your-domain.com]/v2/security_entitlement \
	-H "Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y" \
	-H "Host: example.org" \
	-H "Content-Type: application/json" \
	-H "Cookie: "
```

**Response status**:

```
200 OK
```

**Response body**:

```json
[
  {
  "security_group_guid": "dcee7d89-149b-4bab-9eb9-1e5e73c22aae",
  "organization_guid": "7e0477b9-fff8-41b1-8fd8-969095ba62e5"
  },
  {
    "security_group_guid": "ce9ee907-74a2-4226-a5b2-5b6336973a9e",
    "organization_guid": "11ce76d1-3e17-4479-b090-ff971da597ca"
  }
]
```

#### DELETE /v2/security_entitlement

**Parameters**:
- `organization_guid`: an organisation guid
- `security_group_guid`: a security group to be revoked on the org

**Headers**:

```
Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y
Host: example.org
Content-Type: application/json
Cookie: 
```

**Curl**:

```
curl "https://cfsecurity.[your-domain.com]/v2/security_entitlement -d '{
  "security_group_guid": "dcee7d89-149b-4bab-9eb9-1e5e73c22aae",
  "organization_guid": "7e0477b9-fff8-41b1-8fd8-969095ba62e5"
}' -X DELETE \
	-H "Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y" \
	-H "Host: example.org" \
	-H "Content-Type: application/json" \
	-H "Cookie: "
```

**Response status**:
```
200 OK
```

## Cli plugin

### Installation

<!---
#### Install from plugin repository (recommended)
NOTE: This installation method requires that your client computer has access to the internet.
If internet access is not available from client computer use the manual method.

Verify you have a repo named `CF-Community` registered in your cf client.

```
cf list-plugin-repos
```
If the above command does not show `CF-Community` you can add the repo via:

```
cf add-plugin-repo CF-Community http://plugins.cloudfoundry.org/
```
Now that we have the cloud foundry community repo registered, install `security-entitlement`:

```
cf install-plugin -r CF-Community "security-entitlement"
```

-->
#### Installation from release binaries

1. Download latest release made for your os here: https://github.com/orange-cloudfoundry/cf-security-entitlement/releases
2. run `cf install-plugin path/to/previous/binary/downloaded`


### Commands

```
   disable-security-group                 Revoke an organization to a security group
   enable-security-group                  Entitle an organization to a security group
   entitlement-security-groups            List current security groups entitlements
   manager-security-group                 Show a single security group available for an org manager
   manager-security-groups                List all security groups available for an org manager
   unbind-manager-security-group          Unbind a security group to a particular space, or all existing spaces of an org by an org manager
```

## Terraform-provider-cfsecurity 

This provider has been made to be used with [cloud foundry provider](https://github.com/cloudfoundry-community/terraform-provider-cf)

### Installations

**Requirements:** You need, of course, terraform (**>=0.11**) which is available here: https://www.terraform.io/downloads.html

#### Automatic

To install a specific version, set PROVIDER_CFSECURITY_VERSION before executing the following command

```bash
$ export PROVIDER_CFSECURITY_VERSION="v0.1.0"
```

**via curl**:

```bash
$ bash -c "$(curl -fsSL https://raw.github.com/orange-cloudfoundry/cf-security-entitlement/master/bin/install-provider.sh)"
```

**via wget**:

```bash
$ bash -c "$(wget https://raw.github.com/orange-cloudfoundry/cf-security-entitlement/master/bin/install-provider.sh -O -)"
```

#### Manually

1. Get the build for your system in releases: https://raw.github.com/orange-cloudfoundry/cf-security-entitlement/releases/latest
2. Create a `providers` directory inside terraform user folder: `mkdir -p ~/.terraform.d/providers`
3. Move the provider previously downloaded in this folder: `mv /path/to/download/directory/terraform-provider-cfsecurity ~/.terraform.d/providers`
4. Ensure provider is executable: `chmod +x ~/.terraform.d/providers/terraform-provider-cfsecurity`
5. add `providers` path to your `.terraformrc`:
```bash
cat <<EOF > ~/.terraformrc
providers {
    cfsecurity = "/full/path/to/.terraform.d/providers/terraform-provider-cfsecurity"
}
EOF
```

6. you can now performs any terraform action on cfsecurity resources

### Provider

```hcl
provider "cfsecurity" {
  cf_api_url = "https://api.[your domain]"
  user = "admin user cloud foundry"
  password = "admin password"
  skip_ssl_validation = false
}
```

**Argument Reference**:

The following arguments are supported:

* `cf_api_url` - (Required) API endpoint (e.g. https://api.local.pcfdev.io). This can also be specified
  with the `CF_API_URL` shell environment variable.

* `cf_security_url` - (Optional) This is by default set to `https://cfsecurity.[your domain]` (e.g.: https://cfsecurity.local.pcfdev.io).
  This is the URL to cfsecurity server.
  Can be defined with the `CF_SECURITY_URL` shell environment variable.

* `user` - (Optional) Cloud Foundry user. Defaults to "admin". This can also be specified
  with the `CF_USER` shell environment variable. Unless mentionned explicitly in a resource, CF admin permissions are not required.

* `password` - (Optional) Cloud Foundry user's password. This can also be specified
  with the `CF_PASSWORD` shell environment variable.

* `cf_client_id` - (Optional) The cf client ID to make request with a client instead of user. This can also be specified
  with the `CF_CLIENT_ID` shell environment variable.

* `cf_client_secret` - (Optional) The cf client secret to make request with a client instead of user. This can also be specified
  with the `CF_CLIENT_SECRET` shell environment variable.

* `skip_ssl_validation` - (Optional) Skip verification of the API endpoint - Not recommended!. Defaults to "false". This can also be specified
  with the `CF_SKIP_SSL_VALIDATION` shell environment variable.
  
### Resource cfsecurity_entitle_asg

Entitle a security group to an org.
Resource only manage entitlement previously set in resource. If entitlements has been added by an other way the provider will not override it.

```hcl
resource "cfsecurity_entitle_asg" "my-entitlements" {
  entitle {
    asg_id = "dcee7d89-149b-4bab-9eb9-1e5e73c22aae"
    org_id = "7e0477b9-fff8-41b1-8fd8-969095ba62e5"
  }
  entitle {
    asg_id = "ce9ee907-74a2-4226-a5b2-5b6336973a9e"
    org_id = "11ce76d1-3e17-4479-b090-ff971da597ca"
  }
}
```

**Argument Reference**:
* `entitle` - (Required) A list of entitlements.
  - `asg_id` - (Required, String) a security group to be entitle on the org
  - `org_id` - (Required, String) an organisation guid

### Resource cfsecurity_bind_asg

Bind a security group to an org through cfsecurity server (useful only for org manager who wants to use terraform).
Resource only manage entitlement previously set in resource when `force` is to `false`. If entitlements has been added by an other way the provider will not override it.

```hcl
resource "cfsecurity_entitle_asg" "my-bindings" {
  bind {
    asg_id = "dcee7d89-149b-4bab-9eb9-1e5e73c22aae"
    space_id = "7e0477b9-fff8-41b1-8fd8-969095ba62e5"
  }
  bind {
    asg_id = "ce9ee907-74a2-4226-a5b2-5b6336973a9e"
    space_id = "11ce76d1-3e17-4479-b090-ff971da597ca"
  }
  force = false
}
```

**Argument Reference**:
* `bind` - (Required) A list of entitlements.
  - `asg_id` - (Required, String) a security group to be entitle on the org
  - `space_id` - (Required, String) an organisation guid
* `force` - (Optionnal, boolean) if set to true, resource will overrides security groups assigments for org manager.

### Data source cfsecurity_asg

Retrieve a security group id by its name (useful only for org managers who wants to use terraform)

```hcl
data "cfsecurity_asg" "entitled" {
    name = "entitled"
}
```

**Argument Reference**:
- `name` - (Required) The name of the application security group to lookup

**Attributes Reference**:

The following attributes are exported:
- `id` - The GUID of the application security group
