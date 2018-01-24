use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.socialLogin 400s when there are no args
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            -- Hit non-existent endpoint
            auth0.socialLogin('http://127.0.0.1:19232/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
GET /t
--- ignore_response_body
--- error_code: 400


=== TEST 2: auth0.socialLogin redirects to /authorize and adds the client_id
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialLogin('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
GET /t?response_type=code&connection=Username
--- ignore_response_body
--- response_headers_like
Location: http:\/\/127.0.0.1:1984\/mock\/authorize\?response_type=code&connection=Username&client_id=(\w+)
--- error_code: 302
