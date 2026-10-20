# Caddy LDAP Basic Auth Plugin

This plugin provides a Caddy `caddyauth.Authenticator` provider for HTTP Basic Authentication, using an LDAP server for credential validation and optional group membership checks.

## Features
- Authenticate users against an LDAP/LDAPS server
- Optionally require group membership for access
- Configurable LDAP attributes and connection options
- Structured logging with log levels (debug, info, warn, error)

## Requirements
- Caddy v2.10+
- Go 1.18+
- An accessible LDAP or LDAPS server

## Installation

**Build Caddy with the plugin:**

Use [xcaddy](https://github.com/caddyserver/xcaddy) to build Caddy with this plugin:

```sh
xcaddy build \
  --with github.com/bluewalk/caddy-ldap-basic-auth
```

**OR**

Use caddy's `add-package` to add this plugin

```sh
caddy add-package github.com/bluewalk/caddy-ldap-basic-auth
```

## Configuration

Add the `ldap_basic_auth` directive to your Caddyfile. It configures Caddy's shared authentication handler with the LDAP provider:

```
route {
    ldap_basic_auth {
        ldap_server                 "ldap.example.com:636"
        realm                       "Restricted"
        base_dn                     "ou=users,dc=example,dc=com"
        user_attr                   "uid"
        # For AD lookups, use a read-only account to search for the user's DN.
        ldap_bind_dn                "CN=ldap-reader,OU=Service Accounts,DC=example,DC=com"
        ldap_bind_password          "{$LDAP_BIND_PASSWORD}"
        group_membership_dn         "cn=admins,ou=groups,dc=example,dc=com"
        group_membership_attr       "member"
        use_ldaps
        insecure_skip_verify        # Optional, only for self-signed certs
        pool_size                   5
        ldap_request_timeout        10s
        rate_limit_max_attempts     5
        rate_limit_window_seconds   60
        rate_limit_lockout_seconds  300
    }
    respond "Hello, {http.auth.user.id}!"
}
```

### Directive Options

| Option                    | Type     | Required | Description                                                                                   |
|---------------------------|----------|----------|-----------------------------------------------------------------------------------------------|
| `ldap_server`             | string   | Yes      | Host:port of your LDAP/LDAPS server. |
| `realm`                   | string   | No       | Basic authentication realm shown in the `WWW-Authenticate` challenge (default: `restricted`). |
| `base_dn`                 | string   | Yes      | Base DN for user search (e.g., `ou=users,dc=example,dc=com`). |
| `user_attr`               | string   | Yes      | Attribute for username (e.g., `uid` or `sAMAccountName`). |
| `ldap_bind_dn`             | string   | No       | Bind DN for searching users by `user_attr`; configure together with `ldap_bind_password`. Required by directories, including typical AD setups, that do not allow anonymous searches. |
| `ldap_bind_password`       | string   | No       | Password for the read-only search account. In production, supply it through a Caddy environment placeholder such as `{$LDAP_BIND_PASSWORD}`. |
| `group_membership_dn`     | string   | No       | DN of the group to require membership in. |
| `group_membership_attr`   | string   | No       | Attribute for group membership (default: `member`). |
| `use_ldaps`               | flag     | No       | Use LDAPS (LDAP over TLS). (default: `false`) |
| `insecure_skip_verify`    | flag     | No       | Skip TLS verification (not recommended for production). (default: `false`) |
| `pool_size`               | int      | No       | LDAP connection pool size (default: `5`)
| `ldap_request_timeout`    | duration | No       | Timeout for LDAP bind and search requests, from `1s` to `5m` (default: `10s`). |
| `rate_limit_max_attempts`  | int      | No       | Rate limiting: max attempts (default: `5`) |
| `rate_limit_window_seconds`  | int      | No       | Rate limiting: window in seconds (default: `60`) |
| `rate_limit_lockout_seconds`  | int      | No       | Rate limiting: lockout in seconds (default: `300`) |

When `ldap_bind_dn` is configured, pooled connections stay bound as that search account and are used only for user and group searches. Password verification uses a separate short-lived LDAP connection, so it cannot change the identity of a pooled search connection.

Rate limiting and authentication logs use Caddy's resolved client IP. Behind a reverse proxy, configure Caddy's `trusted_proxies` and `client_ip_headers` as appropriate; the plugin does not read forwarding headers itself. If Caddy's resolved client IP is missing or empty, the provider returns an error.

### Variables
After successful authentication, the Caddy placeholder `{http.auth.user.id}` contains the authenticated username. For example, it can be used in a WebDAV path such as `/var/www/{http.auth.user.id}/data`.

The provider is registered as `http.authentication.providers.ldap`. In JSON, add its configuration under the `providers.ldap` member of an `authentication` handler. The Caddyfile directive above is the simpler equivalent when LDAP is the only provider.

The authentication handler returns HTTP 401 when no provider authenticates the request. LDAP connection, search, and lockout errors are returned to Caddy as provider errors and are available in `{http.auth.ldap.error}` for `handle_errors` customization. The LDAP provider does not write response status codes directly.

When multiple providers are configured under one authentication handler, they are alternatives: a request is authenticated if any provider accepts it. Add only providers that should independently grant access.

## Logging

This plugin uses Caddy's structured logging under the `ldap_basic_auth` logger name. You can control log levels and output in your Caddyfile:

```
logging {
    level debug
    logs {
        default {
            level info
            output stdout
        }
        ldap_basic_auth {
            level debug
            output file /var/log/caddy/ldap_auth.log
        }
    }
}
```

## Example

```
:8080 {
    route {
        ldap_basic_auth {
            ldap_server            "ldap.example.com:636"
            realm                  "Restricted"
            base_dn                "ou=users,dc=example,dc=com"
            user_attr              "uid"
            group_membership_dn    "cn=admins,ou=groups,dc=example,dc=com"
            use_ldaps
        }
        respond "Welcome, {http.auth.user.id}!"
    }
}
```

## Troubleshooting
- Caddyfile users can use the `ldap_basic_auth` handler directive shown above. In JSON, the provider module name is `http.authentication.providers.ldap` and it must be nested under an `authentication` handler.
- The `authentication` handler normally returns 401 for rejected credentials and provider errors. Use `handle_errors` and `{http.auth.ldap.error}` if backend failures or rate limits need a different response status.
- For Active Directory, set `user_attr "sAMAccountName"`, use the domain naming context (for example `DC=medes,DC=internal`) as `base_dn`, and configure a read-only search account with `ldap_bind_dn` and `ldap_bind_password`. The plugin searches for the account DN, then binds as that user to verify the password.
- Check Caddy logs for authentication and LDAP errors.
- Use `insecure_skip_verify` only for testing with self-signed certificates.
- Ensure your LDAP server is reachable from the Caddy host.

## License
MIT
