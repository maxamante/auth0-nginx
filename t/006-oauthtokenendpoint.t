use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.oauthTokenEndpoint 500s when /oauth/token request fails
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            -- Hit non-existent endpoint
            auth0.oauthTokenEndpoint(false, 'http://127.0.0.1:19232/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "grant_type": "password"
}
--- ignore_response_body
--- error_code: 500


=== TEST 2: auth0.oauthTokenEndpoint 500s when the /oauth/token request >= 500
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
            auth0.oauthTokenEndpoint(false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "grant_type": "password"
}
--- ignore_response_body
--- error_code: 500


=== TEST 3: auth0.oauthTokenEndpoint password grant happy path
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
            assert(body['grant_type'] == 'password')
            assert(body['password'] == 'test-pass')
            assert(body['username'] == 'test-user')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.oauthTokenEndpoint(false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "grant_type": "password",
    "username": "test-user",
    "password": "test-pass"
}
--- response_body
{"access_token":"test-access-token"}
--- error_code: 200


=== TEST 4: auth0.oauthTokenEndpoint refresh grant happy path
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
            assert(body['grant_type'] == 'refresh_token')
            assert(body['refresh_token'] == 'test-refresh')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.oauthTokenEndpoint(false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "grant_type": "refresh_token",
    "refresh_token": "test-refresh"
}
--- response_body
{"access_token":"test-access-token"}
--- error_code: 200


=== TEST 5: auth0.oauthTokenEndpoint client credentials grant happy path
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
            -- Check that the client attributes aren't overwritten
            assert(body['client_id'] == 'test-client-id')
            assert(body['client_secret'] == 'test-client-secret')
            assert(body['grant_type'] == 'client_credentials')

            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                access_token = 'test-access-token'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.oauthTokenEndpoint(false, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "grant_type": "client_credentials",
    "client_id": "test-client-id",
    "client_secret": "test-client-secret"
}
--- response_body
{"access_token":"test-access-token"}
--- error_code: 200


=== TEST 6: auth0.oauthTokenEndpoint password grant happy path with includeUser
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_MGMT_AUDIENCE;
--- config
    location = /mock/oauth/token {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            ngx.log(ngx.DEBUG, cjson.encode(body))
            if (body['audience']) then
                assert(body['client_id'])
                assert(body['client_secret'])
                assert(body['audience'])
                assert(body['grant_type'] == 'client_credentials')

                ngx.header.content_type = 'application/json'
                ngx.say(cjson.encode({
                    access_token = 'test-mgmt-access-token'
                }))
                ngx.exit(200)
            else
                ngx.log(ngx.DEBUG, cjson.encode(body))
                assert(body['client_id'])
                assert(body['client_secret'])
                assert(body['grant_type'] == 'password')
                assert(body['password'] == 'test-pass')
                assert(body['username'] == 'test-user')

                ngx.header.content_type = 'application/json'
                ngx.say(cjson.encode({
                    access_token = 'test-access-token',
                    id_token = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImp0aSI6ImJjY2MwZWRmLThhOWUtNGVlZC1iOGY1LWMxZDE1ZTc5ZTFhZSIsImlhdCI6MTUxNjgyMjk0OSwiZXhwIjoxNTE2ODI2NTQ5fQ.trOwscmTZStE8R8ZZvVF1jY7teD4Eyda9yRDRm13s8I'
                }))
                ngx.exit(200)
            end
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

    location = /mock/api/v2/users/1234567890 {
        content_by_lua_block {
            local cjson = require('cjson')
            ngx.header.content_type = 'application/json'
            ngx.say(cjson.encode({
                email = 'test-user@example.com',
                user = 'test-user',
                otherkey = 'test-otherkey'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.oauthTokenEndpoint(true, 'http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "grant_type": "password",
    "username": "test-user",
    "password": "test-pass"
}
--- response_body
{"user":{"user":"test-user","email":"test-user@example.com","otherkey":"test-otherkey"},"auth":{"id_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImp0aSI6ImJjY2MwZWRmLThhOWUtNGVlZC1iOGY1LWMxZDE1ZTc5ZTFhZSIsImlhdCI6MTUxNjgyMjk0OSwiZXhwIjoxNTE2ODI2NTQ5fQ.trOwscmTZStE8R8ZZvVF1jY7teD4Eyda9yRDRm13s8I","access_token":"test-access-token"}}
--- error_code: 200
