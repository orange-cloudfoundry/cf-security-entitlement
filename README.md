# cf-security-entitlement

Add an entitlement mechanism similar to [isolation segment](https://docs.cloudfoundry.org/adminguide/isolation-segments.html#relationships) on Cloud Foundry.

This is providing entitlement on security group which permit to a cloud foundry admin to authorize an org manager to place 
security groups (previously allowed by an admin) himself on space.

This project has 3 parts:
- **server**: api which enable entitlement and security groups placement for org manager. 
**Must be deployed beside cc api through the bosh release https://github.com/orange-cloudfoundry/cf-security-entitlement-boshrelease**
- **cli plugin**: A Cloud Foundry cli plugin which add commands for this api
- **terraform provider**: A [terraform](http://terraform.io/) provider which use api to entitle security groups and which 
can be combined with [cloud foundry provider](https://github.com/cloudfoundry-community/terraform-provider-cf) **NOW ON ITS OWN REPO AT https://github.com/orange-cloudfoundry/terraform-provider-cfsecurity**

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

#### GET /v3/security_groups/<security_group_guid>/relationships/spaces/<space_guid>/check

Check if space has its org entitle with this security group guid

**Url Parameters**:
- `security_group_guid`: a security guid to check
- `space_guid`: a space guid to check

**Headers**:

```
Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y
Host: example.org
Content-Type: application/json
Cookie: 
```

**Curl**:

```
curl "https://cfsecurity.[your-domain.com]/v3/security_groups/23a073f5-00e7-425b-b046-de45ba9b5456/relationships/spaces/4ad3d6c7-80a9-4655-866f-aa0f71d95183/check \
	-H "Authorization: bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoidWFhLWlkLTkiLCJlbWFpbCI6ImVtYWlsLTlAc29tZWRvbWFpbi5jb20iLCJzY29wZSI6WyJjbG91ZF9jb250cm9sbGVyLmFkbWluIl0sImF1ZCI6WyJjbG91ZF9jb250cm9sbGVyIl0sImV4cCI6MTQ2NjAwODg4MX0.r0oLFGpSuuUWDIpqwuZ6X_8xhkqhspKEOhDYQdRzu9Y" \
	-H "Host: example.org" \
```

**Response status**:
```
200 OK
```

**Response body**:

```json
{
  "is_entitled": true,
  "organization_guid": "7e0477b9-fff8-41b1-8fd8-969095ba62e5"
}
```

## Cli plugin

### Installation from release binaries

1. Download latest release made for your os here: https://github.com/orange-cloudfoundry/cf-security-entitlement/releases
2. run `cf install-plugin path/to/previous/binary/downloaded`


### Commands

#### Admin Role

```
   disable-security-group                 Revoke an organization to a security group
   enable-security-group                  Entitle an organization to a security group
   entitlement-security-groups            List current security groups entitlements
   clean-security-group-entitlements      Remove all unconsistent security group entitlements
```

#### OrgManager Role

```
   manager-security-group                 Show a single security group available for an org manager
   manager-security-groups                List all security groups available for an org manager
   bind-manager-security-group            Bind a security group to a particular space
   unbind-manager-security-group          Unbind a security group to a particular space
```


## Terraform-provider-cfsecurity 

You can found provider on its own repository at https://github.com/orange-cloudfoundry/terraform-provider-cfsecurity and its documentation on terraform: https://registry.terraform.io/providers/orange-cloudfoundry/cfsecurity/latest/docs
