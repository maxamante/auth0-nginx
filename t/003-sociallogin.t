use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.socialLogin 302s the user to auth0 authorize endpoint
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.socialLogin()
        }
    }
--- request
GET /t?response_type=token&connection=User-Connection
--- error_code: 302
