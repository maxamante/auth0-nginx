use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.signup 500s when /dbconnections/signup request fails
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            -- Hit non-existent endpoint
            auth0.signup('http://127.0.0.1:19232/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "email": "test-user@example.com",
    "password": "test-pass"
}
--- ignore_response_body
--- error_code: 500


=== TEST 2: auth0.signup 500s when /dbconnections/signup request >= 500
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/dbconnections/signup {
        content_by_lua_block {
            ngx.header.content_type = 'application/json'
            ngx.exit(503)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.signup('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "email": "test-user@example.com",
    "password": "test-pass"
}
--- ignore_response_body
--- error_code: 500


=== TEST 3: auth0.signup happy path
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_CLIENT_CONNECTION;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /mock/dbconnections/signup {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            ngx.log(ngx.DEBUG, cjson.encode(body))
            assert(body['client_id'])
            assert(body['connection'])
            assert(body['password'] == 'test-pass')
            assert(body['email'] == 'test-user@example.com')

            ngx.header.content_type = 'application/json'
            -- Include key that shouldn't be included in the response
            ngx.say(cjson.encode({
                email = body['email'],
                email_verified = false,
                some_other_key = 'test-other-key'
            }))
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.signup('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "email": "test-user@example.com",
    "password": "test-pass"
}
--- response_body
{"email":"test-user@example.com","email_verified":false}
--- error_code: 200


=== TEST 4: auth0.signup email not allowed
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.signup('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "email": "test-user@notallowed.com",
    "password": "test-pass"
}
--- ignore_response_body
--- error_code: 412
