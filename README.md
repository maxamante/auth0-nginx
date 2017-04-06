# Auth0 Nginx Integration

This is an Auth0 integration written in Lua for the nginx web server.

This integration allows you to use nginx as an API Gateway for your backend, without integrating Auth0 into every service.

# Why use an nginx plugin?

Instead of installing an Auth0 integration into each one of your microservices' codebases, you can instead have nginx handle your authentication. Integrating Auth0 into your nginx.conf file is as easy as:

```nginx
location /api/ {
    access_by_lua_block {
        local auth0 = require("auth0-nginx")
        auth0.requireAccount()
    }
    proxy_pass http://localhost:3000/;
}
```

When a user makes a request to `/api/*`, Auth0 will look for and validate an access token for the request. If no access token is found, Auth0 will ask nginx to render a `401 Unauthorized` page.

The Auth0 nginx integration also exposes an OAuth 2.0 endpoint that can issue access and refresh tokens for authenticated users.

# Installation

Auth0's nginx integration requires the use of [OpenResty](https://openresty.org/). To use the nginx integration, make sure you have the following installed and configured:

* [OpenResty](https://openresty.org/) - a distribution of the nginx web server that includes the lua plugin
* [Lua](https://www.lua.org/download.html) - the Lua programming language
* [Luarocks](https://github.com/keplerproject/luarocks/wiki/Download) - a Lua package manager

If you're new to OpenResty, the following tips will help you make sure you configure Lua properly:

* When installing Lua, don't forget to `sudo make install` after building Lua with `make linux test`
* You should add Luarocks modules to your lua path by running this command and adding it to your `.bash_profile` file: `eval $(luarocks path --bin)`. Otherwise, nginx will not detect your Luarocks modules.

With Luarocks, you can install the Auth0 nginx plugin with:

```bash
$ luarocks install auth0-nginx --local
```

# Usage

If it's your first time using OpenResty, check out the [Getting Started with OpenResty](https://openresty.org/en/getting-started.html) guide on how to configure and run nginx. You should also take a look at the [example.nginx.conf](example.nginx.conf) file to see how an nginx.conf file is structured.

The Auth0 plugin allows you to perform access control by adding code in the `access_by_lua_block` hooks exposed by OpenResty. Nginx will first run your code in the `access_by_lua_block`, and depending on the result, optionally pass the request onto your content handler.

## Configuring the Auth0 API Key and Secret

As with any other Auth0 integration, the Auth0 nginx plugin reads environment variables to find the API Key and Secret for Auth0. Sign into the [Auth0 admin console]() to find your API Key and secret, and by running these and adding to your `.bash_profile`:

```
export AUTH0_APIKEY_ID=
export AUTH0_APIKEY_SECRET=
export AUTH0_CLIENT_HREF=
```

With nginx, you need to explicitly expose environment variables to modules in the configuration, so you need to add into the top level configuration:

```
env AUTH0_APIKEY_ID;
env AUTH0_APIKEY_SECRET;
env AUTH0_CLIENT_HREF;
```

Note: `AUTH0_CLIENT_HREF` is optional for the Auth0 nginx plugin.

## Authentication Scheme

The Auth0 nginx plugin expects API clients to authenticate with Auth0 access tokens presented as a Bearer token. This looks like the following:

```http
GET / HTTP/1.1
Authorization: Bearer eyJra...
```

These tokens are validated locally using the Auth0 API Key and Secret pair.

## Getting the Authenticated Account

You can use the Auth0 plugin to check for an access token, and forward the account details to the end application. Here's what the configuration would look like.

```nginx
location /api/ {
    access_by_lua_block {
        local auth0 = require("auth0-nginx")
        auth0.getAccount()
    }
    proxy_pass http://localhost:3000/;
}
```

In this example, nginx will proxy all requests to `http://localhost:3000/`.

## Requiring Authentication

As a convenience, you can also have the Auth0 plugin only allow requests with a valid access token. In this example, Auth0 will deny requests with the default nginx `401 Unauthorized` handler.

```nginx
server {
    listen 8080;
    error_page 401 /empty;
    location /api/ {
        access_by_lua_block {
            local auth0 = require("auth0-nginx")
            auth0.requireAccount()
        }
        proxy_pass http://localhost:3000/;
    }
    location /empty {
        internal;
        return 200 '';
    }
}
```

Note: Since the default nginx `401 Unauthorized` page is a HTML page, this example shows how to override the default handler and instead return an empty body.

## OAuth Token Endpoint

Auth0's nginx plugin can also act as an OAuth 2.0 endpoint and issue Auth0 access and refresh tokens. The OAuth handler supports the `password` and `refresh` grant types.

Since this endpoint requires connectivity to Auth0, you need to configure nginx to use a DNS resolver, as well as a pem file with your trusted SSL certificates. Add this into your http configuration block:

```nginx
resolver 4.2.2.4;
lua_ssl_trusted_certificate /path/to/your/root/ca/pem/file;
lua_ssl_verify_depth 2;
```

Note: If you're unsure where your root certificate pem file is, check out Go's [root CA search paths](https://golang.org/src/crypto/x509/root_linux.go). The referenced root CA files should work for your linux distribution. If you're on macOS, you'll need to open up Keychain Access, select all of your System Roots certificates, and then go to File > Export Items to export a .pem file.

Once you have nginx configured, you can add an OAuth endpoint with the following configuration:

```nginx
location = /oauth/token {
    content_by_lua_block {
        local auth0 = require('auth0-nginx')
        auth0.oauthTokenEndpoint()
    }
}
```

The `oauthTokenEndpoint` method requires the environment variable `AUTH0_CLIENT_HREF` to be set and exposed as well. Alternatively, you can call the method and pass in an application href :

```nginx
auth0.oauthTokenEndpoint('https://AUTH0_SUBDOMAIN.auth0.com')
```

## Using the OAuth token endpoint

The OAuth token endpoint supports the password, refresh, and client credentials grant types. More information can be found in the [OAuth spec](https://tools.ietf.org/html/rfc6749), but here's a general overview:

### Password Grant Type

You can get an access token with the following HTTP request:

```http
POST /oauth/token

{
  "grant_type":"password",
  "username":<username>,
  "password":<password>
}
```

This will respond with the following:

```http
HTTP/1.1 200 OK

{
  "access_token":"2YotnFZFEjr1zCsicMWpAA",
  "expires_in":3600,
  "refresh_token":"tGzv3JOkF0XG5Qx2TlKWIA",
  "token_type":"Bearer"
}
```

Or, deny the request:

```http
HTTP/1.1 400 Bad Request

{
  "error": "invalid_grant",
  "message": "Invalid username or password."
}
```

### Refresh Grant Type

After the access token expires, you might want to get a new one. If your refresh token is still valid, you can use the refresh grant to get a new access token, and expect the same response as above:

```http
POST /oauth/token

{
  "grant_type":"refresh_token",
  "refresh_token":<refresh token>
}
```

### Client Credentials

The OAuth token endpoint also supports the client credentials grant type, which is used to exchange a set of API Keys for an access token. The following request is made, using Basic Authentication with the API Key ID as the username, and API Key Secret as the password:

```http
POST /oauth/token

{
  "grant_type":"client_credentials",
  "client_id":<client_id>,
  "client_secret":<client_secret>
}
```

This results in the following access token response (or above error response). Note that unlike the password grant type, no refresh token is issued. This is because the API Key / Secret are used to "refresh" the access token.

```http
{
  "access_token": "eyJra...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

# Tests

Tests are run using the `Test::Nginx` CPAN module. Install it via:

```bash
$ cpan Test::Nginx
```

Then you can run the tests using:

```bash
$ prove t/*.t
```

# Questions?

We're proud of the support we provide. Feel free to open up a GitHub issue!
