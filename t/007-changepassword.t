use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.changePassword 500s when /dbconnections/change_password request fails
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            -- Hit non-existent endpoint
            auth0.changePassword('http://127.0.0.1:19232/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "email": "test-user@example.com"
}
--- ignore_response_body
--- error_code: 500


=== TEST 2: auth0.changePassword 500s when /dbconnections/change_password request >= 500
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/dbconnections/change_password {
        content_by_lua_block {
            ngx.header.content_type = 'application/json'
            ngx.exit(503)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.changePassword('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "email": "test-user@example.com"
}
--- ignore_response_body
--- error_code: 500


=== TEST 3: auth0.changePassword happy path
--- ONLY
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /mock/dbconnections/change_password {
        content_by_lua_block {
            local cjson = require('cjson')
            local headers = ngx.req.get_headers()
            assert(headers['content-type'] == 'application/json')

            ngx.req.read_body()
            local body = cjson.decode(ngx.req.get_body_data())
            assert(body['email'] == 'test-user@example.com')

            ngx.header.content_type = 'application/json'
            ngx.say("We've just sent you an email to reset your password.")
            ngx.exit(200)
        }
    }

    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.changePassword('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
POST /t
{
    "email": "test-user@example.com"
}
--- response_body
"We've just sent you an email to reset your password.\n"
--- error_code: 200
