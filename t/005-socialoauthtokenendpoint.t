use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.socialOauthTokenEndpoint 500s when /oauth/token request fails
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(true, false, 'http://127.0.0.1:19232/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- ignore_response_body
--- error_code: 500


=== TEST 2: auth0.socialOauthTokenEndpoint 500s when the /oauth/token request >= 500
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            ngx.header.content_type = 'application/json'
            ngx.exit(503)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(true, false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- ignore_response_body
--- error_code: 500


=== TEST 3: auth0.socialOauthTokenEndpoint 500s when the /userinfo request fails
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            ngx.header.content_type = 'application/json'
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(true, false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- ignore_response_body
--- error_code: 500


=== TEST 4: auth0.socialOauthTokenEndpoint 500s when the /userinfo request >= 500
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            ngx.header.content_type = 'application/json'
            ngx.exit(200)
        }
    }

    location = /mock/userinfo {
        content_by_lua_block {
            ngx.header.content_type = 'application/json'
            ngx.exit(503)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(true, false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- ignore_response_body
--- error_code: 500


=== TEST 5: auth0.socialOauthTokenEndpoint happy path
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            assert(body['client_id'])
            assert(body['client_secret'])
            assert(body['code'] == 'test-code')
            assert(body['grant_type'] == 'authorization_code')
            assert(body['redirect_uri'] == 'test-redirect-url')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /mock/userinfo {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['authorization'] == 'Bearer test-access-token')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                email = 'test-user@example.com',
                user = 'test-user'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(false, false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- response_body
{"access_token":"test-access-token"}
--- error_code: 200


=== TEST 6: auth0.socialOauthTokenEndpoint happy path with verify
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            assert(body['client_id'])
            assert(body['client_secret'])
            assert(body['code'] == 'test-code')
            assert(body['grant_type'] == 'authorization_code')
            assert(body['redirect_uri'] == 'test-redirect-url')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /mock/userinfo {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['authorization'] == 'Bearer test-access-token')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                email = 'test-user@example.com',
                user = 'test-user'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(true, false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- response_body
{"access_token":"test-access-token"}
--- error_code: 200


=== TEST 7: auth0.socialOauthTokenEndpoint happy path with verify failure
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            assert(body['client_id'])
            assert(body['client_secret'])
            assert(body['code'] == 'test-code')
            assert(body['grant_type'] == 'authorization_code')
            assert(body['redirect_uri'] == 'test-redirect-url')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /mock/userinfo {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['authorization'] == 'Bearer test-access-token')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                email = 'test-user@notallowed.com',
                user = 'test-user'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(true, false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- ignore_response_body
--- error_code: 412


=== TEST 8: auth0.socialOauthTokenEndpoint happy path with includeUser
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            assert(body['client_id'])
            assert(body['client_secret'])
            assert(body['code'] == 'test-code')
            assert(body['grant_type'] == 'authorization_code')
            assert(body['redirect_uri'] == 'test-redirect-url')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /mock/userinfo {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['authorization'] == 'Bearer test-access-token')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                email = 'test-user@example.com',
                user = 'test-user'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(false, true, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- response_body
{"user":{"user":"test-user","email":"test-user@example.com"},"auth":{"access_token":"test-access-token"}}
--- error_code: 200


=== TEST 9: auth0.socialOauthTokenEndpoint happy path with verify and includeUser
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            assert(body['client_id'])
            assert(body['client_secret'])
            assert(body['code'] == 'test-code')
            assert(body['grant_type'] == 'authorization_code')
            assert(body['redirect_uri'] == 'test-redirect-url')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /mock/userinfo {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['authorization'] == 'Bearer test-access-token')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                email = 'test-user@example.com',
                user = 'test-user'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialOauthTokenEndpoint(true, true, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "code": "test-code",
    "grant_type": "authorization_code",
    "redirect_uri": "test-redirect-url"
}
--- response_body
{"user":{"user":"test-user","email":"test-user@example.com"},"auth":{"access_token":"test-access-token"}}
--- error_code: 200
