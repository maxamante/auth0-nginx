# Auth0 Nginx Integration

This is an Auth0 integration written in Lua for the nginx web server.

This integration allows you to use nginx as an API Gateway for your backend without integrating Auth0 into every service.

# Why use an nginx plugin?

Instead of installing an Auth0 integration into each one of your microservices' codebases, you can instead have nginx handle your authentication. Integrating Auth0 into your nginx.conf file is as easy as:

```nginx
location /api/ {
    access_by_lua_block {
        local auth0 = require("auth0-nginx")
        auth0.requireAccount(os.getenv("API_KEY"), os.getenv("API_AUD"))
    }
    proxy_pass http://localhost:3000/;
}
```

When a user makes a request to `/api/*`, Auth0 will look for and validate an access token for the request. If no access token is found or an access token with mismatching signature key and/or audience is found, nginx will render a `401 Unauthorized` page. For more information, please read through [this token verification documentation](https://auth0.com/docs/api-auth/tutorials/verify-access-token#check-the-signature-algorithm).

The Auth0 nginx integration also exposes an OAuth 2.0 endpoint that can issue access and refresh tokens for authenticated users, as well as signup and change password endpoints.

# Installation

Auth0's nginx integration requires the use of [OpenResty](https://openresty.org/). To use the nginx integration, make sure you have the following installed and configured:

* [OpenResty](https://openresty.org/) - a distribution of the nginx web server that includes the lua plugin
* [Lua](https://www.lua.org/download.html) - the Lua programming language
* [Luarocks](https://github.com/keplerproject/luarocks/wiki/Download) - a Lua package manager

If you're new to OpenResty, the following tips will help you make sure you configure Lua properly:

* When installing Lua, don't forget to `sudo make install` after building Lua with `make linux test`
* You should add Luarocks modules to your lua path by running this command and adding it to your `.bash_profile` file: `eval $(luarocks path --bin)`. Otherwise, nginx will not detect your Luarocks modules.

With Luarocks, you can install the Auth0 nginx plugin with:

```shell
luarocks install auth0-nginx --local
```

# Usage

If it's your first time using OpenResty, check out the [Getting Started with OpenResty](https://openresty.org/en/getting-started.html) guide on how to configure and run nginx. You should also take a look at the [example.nginx.conf](example.nginx.conf) file to see how an nginx.conf file is structured.

The Auth0 plugin allows you to perform access control by adding code in the `access_by_lua_block` hooks exposed by OpenResty. Nginx will first run your code in the `access_by_lua_block`, and depending on the result, optionally pass the request onto your content handler.

## Configuring the Auth0 API Key and Secret

As with any other Auth0 integration, the Auth0 nginx plugin reads environment variables to find the client key, secret, user database connection and domain for Auth0. Sign into your Auth0 admin console to find your client key, secret, user database connection and domain by running these and adding to your `.bash_profile`:

```shell
export AUTH0_ACCOUNT_DOMAIN=
export AUTH0_CLIENT_ID=
export AUTH0_CLIENT_SECRET=
export AUTH0_CLIENT_CONNECTION=<User database connection name>
```

With nginx, you need to explicitly expose environment variables to modules in the configuration, so you need to add into the top level configuration:

```nginx
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_CLIENT_CONNECTION;
env AUTH0_ACCOUNT_DOMAIN;
```

You also need to declare and expose a pair of key/audience values per endpoint that nginx will be providing authentication. E.g. If you have a `service1` endpoint:

```shell
export SERVICE1_AUD=<Identifier near top of the Settings page of an API>
export SERVICE1_SECRET=<Signing secret near the bottom of the Settings page of an API>
```

Again expose them in the top level configuration of your nginx.conf file:

```nginx
env SERVICE1_AUD;
env SERVICE1_SECRET;
```

Note: Instead of calling `getAccount` or `requireAccount` as shown above you can also declare nginx variables in a server and/or location level configuration and call it like:

```nginx
server {
    ...

    set_by_lua $service1_secret 'return os.getenv("SERVICE1_SECRET")';
    set_by_lua $service1_aud 'return os.getenv("SERVICE1_AUD")';

    location / {
        access_by_lua_block {
            local auth0 = require("auth0-nginx")
            auth0.requireAccount(ngx.var.service1_secret, ngx.var.service1_aud)
        }
        proxy_pass http://localhost:3000/;
    }

    ...
}
```

The `getAccount` and `requireAccount` methods require the environment variable `AUTH0_ACCOUNT_DOMAIN` to be set and exposed as well. Alternatively, you can call the method and pass in an application URL:

```lua
auth0.getAccount(ngx.var.service1_secret, ngx.var.service1_aud, 'https://ACCOUNT_DOMAIN.auth0.com')
auth0.requireAccount(ngx.var.service1_secret, ngx.var.service1_aud, 'https://ACCOUNT_DOMAIN.auth0.com')
```

## Authentication Scheme

The Auth0 nginx plugin expects API clients to authenticate with Auth0 access tokens presented as a Bearer token. This looks like the following:

```http
GET / HTTP/1.1
Authorization: Bearer eyJra...
```

These tokens are validated locally using the Auth0 client secret, account domain, and intended audience.

## Getting the Authenticated Account

It is recommended that you use the `openid` scope when requesting a user's `access_token`. Using this scope will return an `id_token` with your `access_token`. You can use the access and id tokens received by the Auth0 plugin and send a GET request to an endpoint using `getAccount` and `requireAccount` using the following headers:

```http
GET /getAccount HTTP/1.1
Authorization: Bearer <ACCESS_TOKEN>
X-Auth0-Account-Token: <ID_TOKEN>
```

The response will have the `X-Auth0-Account` header which will hold a stringified JSON object of the authenticated user's account information that will resemble the following:

```json
{
  "name": "test.user@example.com",
  "nickname": "test.user",
  "picture": "https://s.gravatar.com/avatar/profile_photo.png",
  "updated_at": "2016-04-20T16:20:00.420Z",
  "email": "test.user@example.com",
  "email_verified": false,
}
```

## Requiring Authentication

As a convenience, you can also have the Auth0 plugin only allow requests with a valid access token. In this example, Auth0 will deny requests with the default nginx `401 Unauthorized` handler. This method can also be used to get the authenticated user's account using the instructions above.

```nginx
server {
    listen 8080;
    error_page 401 /empty;
    location /api/ {
        access_by_lua_block {
            local auth0 = require("auth0-nginx")
            auth0.requireAccount(os.getenv("API_KEY"), os.getenv("API_AUD"))
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

## OAuth Token endpoint

Auth0's nginx plugin can also act as an OAuth 2.0 endpoint and issue Auth0 access and refresh tokens. The OAuth handler supports the `client_credentials`, `password` and `refresh_token` grant types.

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

If you want to include the user's extended account in the response, you can enable this with the following (this is disabled by default):

```lua
auth0.oauthTokenEndpoint(true)
```

Note: Returning the user's extended account is only supported through the Password Grant type.

The `oauthTokenEndpoint` method requires the environment variable `AUTH0_ACCOUNT_DOMAIN` to be set and exposed as well. Alternatively, you can call the method and pass in an application URL:

```lua
auth0.oauthTokenEndpoint(<true|false>, 'https://ACCOUNT_DOMAIN.auth0.com')
```

## Using the OAuth token endpoint

The OAuth token endpoint supports the password, refresh, and client credentials grant types. More information can be found in the [OAuth spec](https://tools.ietf.org/html/rfc6749), but here's a general overview:

### Password Grant Type

You can get an access token with the following HTTP request:

```http
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "password",
  "username": <username>,
  "password": <password>
}
```

This will respond with the following:

```http
HTTP/1.1 200 OK

{
  "access_token": "2kjdiJRNnd...",
  "expires_in": 3600,
  "token_type": "Bearer"
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

If you're including the user's extended account, the response will have this form:

```http
HTTP/1.1 200 OK

{
    "auth": {
        "access_token": "23krwj...",
        ...
    },
    "user": {
        "email": "test.email@example.com",
        ...
    }
}
```

Note: You can request a `refresh_token` by enabling the ability to work offline from Auth0 and adding the `offline_access` scope to your request.

### Refresh Grant Type

After the access token expires, you might want to get a new one. If your refresh token is still valid, you can use the refresh grant to get a new access token, and expect the same response as above:

```http
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "refresh_token",
  "refresh_token": <refresh_token>
}
```

### Client Credentials

The OAuth token endpoint also supports the client credentials grant type, which is used to exchange a set of API Keys for an access token:

```http
POST /oauth/token
Content-Type: application/json

{
  "grant_type": "client_credentials",
  "client_id": <client_id>,
  "client_secret": <client_secret>
}
```

This results in the following access token response (or above error response). Note that unlike the password grant type, no refresh token can be requested. This is because the API Key / Secret are used to "refresh" the access token.

```http
{
  "access_token": "eyJra...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

## Signup endpoint

Auth0's nginx plugin can also act as a Signup endpoint.

Since this endpoint requires connectivity to Auth0, you need to configure nginx to use a DNS resolver, as well as a pem file with your trusted SSL certificates, see the OAuth Token Endpoint docs above.

Once you have nginx configured, you can add a Signup endpoint with the following configuration:

```nginx
location = /signup {
    content_by_lua_block {
        local auth0 = require('auth0-nginx')
        auth0.signup()
    }
}
```

Like the OAuth Token endpoint, the `signup` method requires the environment variable `AUTH0_ACCOUNT_DOMAIN` to be set and exposed as well. Alternatively, you can call the method and pass in an application URL:

```lua
auth0.signup('https://ACCOUNT_DOMAIN.auth0.com')
```

The Signup endpoint can be configured to restrict signups to specific domains. This feature is implicitly turned on by declaring and exposing the `AUTH0_WHITELIST_DOMAINS` environment variable. This should be a comma separated value of domains allowed to sign up:

```shell
export AUTH0_WHITELIST_DOMAINS=google.com,facebook.com,amazon.com
```

When this variable is set, nginx will check that the domain is whitelisted. If the domain is not part of the whitelist, execution will end and a HTTP 412 will be returned.

### Using the Signup endpoint

You can allow sign up with the following HTTP requests:

```http
POST /signup
Content-Type: application/json

{
  "email": <email>,
  "password": <password>
}
```

This will respond with the following (or above error response):

```http
HTTP/1.1 200 OK

{
  "_id": "58457fe6b27...",
  "email_verified": false,
  "email": <email>
}
```

## Change Password endpoint

Auth0's nginx plugin can also act as a Change Password endpoint.

Since this endpoint requires connectivity to Auth0, you need to configure nginx to use a DNS resolver, as well as a pem file with your trusted SSL certificates, see the OAuth Token Endpoint docs above.

Once you have nginx configured, you can add a Change Password endpoint with the following configuration:

```nginx
location = /change_password {
    content_by_lua_block {
        local auth0 = require('auth0-nginx')
        auth0.changePassword()
    }
}
```

Like the OAuth Token or Signup endpoint, the `changePassword` method requires the environment variable `AUTH0_ACCOUNT_DOMAIN` to be set and exposed as well. Alternatively, you can call the method and pass in an application URL:

```lua
auth0.changePassword('https://ACCOUNT_DOMAIN.auth0.com')
```

### Using the Change Password endpoint

You can allow password change requests with the following HTTP requests:

```http
POST /change_password
Content-Type: application/json

{
    "email": <email>
}
```

This will respond with the following (or above error response):

```http
HTTP/1.1 200 OK

"We've just sent you an email to reset your password."
```

## Social Login endpoint

Auth0's nginx plugin can also act as a Social Login endpoint. In combination with the Social OAuth Token endpoint, you can use both `response_type`s allowed by Auth0.

Once you have nginx configured, you can use the endpoint with the following configuration:

```nginx
location = /social_login {
    content_by_lua_block {
        local auth0 = require('auth0-nginx')
        auth0.socialLogin()
    }
}
```

This endpoint is a proxy to Auth0's `authorize` endpoint. Please refer to the [Auth0's Social documentation](https://auth0.com/docs/api/authentication#social) for more information.

Like with the OAuth Token endpoint, the `socialLogin` method requires the environment variable `AUTH0_ACCOUNT_DOMAIN` to be set and exposed as well. Alternatively, you can call the method and pass in an application href:

```lua
auth0.socialLogin('https://ACCOUNT_DOMAIN.auth0.com')
```

### Using the Social Login endpoint

You can allow social login by redirecting your users with the following HTTP request:

```http
GET /social_login?
    response_type=<code|token>
    &connection=<social login connection>
    &additional-parameter=<additional parameters>
    &redirect_uri=<URL to redirect to after login>
    &state=<opaque string>
```

This will redirect your user to the social identity provider's permissions grant page.

## Social OAuth Token endpoint

Auth0's nginx plugin can also act as the server-side in an `authorization_code` grant. Currently, this is implemented to work with the Social Login endpoint and is not tested for other `authorization_code` grant flows, but may still work as expected.

Once you have nginx configured, you can use the endpoint with the following configuration:

```nginx
location = /oauth/social_token {
    content_by_lua_block {
        local auth0 = require('auth0-nginx')
        auth0.socialOauthTokenEndpoint()
    }
}
```

If you want to restrict login with a social account to the domains declared in `AUTH0_WHITELIST_DOMAINS`, you can enable this with the following (this is disabled by default):

```lua
auth0.socialOauthTokenEndpoint(true)
```

If you want to include the user's extended account in the response, you can enable this with the following (this is disabled by default):

```lua
auth0.socialOauthTokenEndpoint(<true|false>, true)
```

Additionally, like the OAuth Token endpoint, the `socialOauthTokenEndpoint` method requires the enviroment variable `AUTH0_ACCOUNT_DOMAIN` to be set and exposed as well. Alternatively, you can call the method and pass in an application URL:

```lua
auth0.socialOauthTokenEndpoint(<true|false>, <true|false>, 'https://ACCOUNT_DOMAIN.auth0.com')
```

### Using the Social OAuth Token endpoint

You can continue an `authorization_code` grant flow with the following HTTP request:

```http
POST /oauth/social_token

{
    "grant_type": "authorization_code",
    "code": <authorization_code>,
    "redirect_uri": <Redirection on success>
}
```

This will respond with the following (or above error response):

```http
HTTP/1.1 200 OK

{
  "access_token": "2kjdiJRNnd...",
  "expires_in": 3600,
  "token_type": "Bearer"
}
```

If you're including the user's extended account, the response will have the following form:

```http
HTTP/1.1 200 OK

{
    "auth": {
        "access_token": "23krwj...",
        ...
    },
    "user": {
        "email": "test.email@example.com",
        ...
    }
}
```

In the response, `auth` will hold a JSON object similar to one issued by the `oauthTokenEndpoint` and `user` will hold a JSON object similar to one issued by the `getAccount`/`requireAccount` methods.

## Verify Account endpoint

Auth0's nginx plugin can also act as an account verifier; verifying that the account is part of the whitelisted domains.

Once you have nginx configured, you can use the endpoint with the following configuration:

```nginx
location = /verify {
    content_by_lua_block {
        local auth0 = require('auth0-nginx')
        auth0.verifyAccount()
    }
}
```

Like the OAuth Token endpoint, the `verifyAccount` method requires the enviroment variable `AUTH0_ACCOUNT_DOMAIN` to be set and exposed as well. Alternatively, you can call the method and pass in an application href:

```lua
auth0.verifyAccount('https://ACCOUNT_DOMAIN.auth0.com')
```

### Using the Verify Account endpoint

You can allow account verification with the following HTTP request:

```http
GET /verify
Authorization: <Bearer Token>
X-Auth0-Account-Token: <ID Token>
```

This will respond with the user's account (parsed from the ID Token) if the domain is whitelisted similar to the following response (or with an HTTP 412 if the domain is not allowed):

```http
HTTP/1.1 200 OK

{
    "email": "test.email@example.com",
    "name": "test.email@example.com",
    "email_verified": false
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
