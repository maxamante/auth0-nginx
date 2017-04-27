use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: nginx doesn't crash when using the Auth0 module
As long as the required environment variables are set, nothing should explode
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require("auth0-nginx")
            ngx.print(os.getenv('AUTH0_CLIENT_ID') == nil or os.getenv('AUTH0_CLIENT_SECRET') == nil)
        }
    }
--- request
GET /t
--- response_body: false
--- error_code: 200


=== TEST 2: nginx should explode if environment variables aren't set
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require("auth0-nginx")
        }
    }
--- request
GET /t
--- error_code: 500
