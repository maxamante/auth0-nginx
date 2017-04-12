use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: nginx doesn't crash when using the Auth0 module
--- config
  location = /t {
    content_by_lua_block {
      local auth0 = require("auth0-nginx")
    }
  }
--- request
GET /t
--- error_code: 200

=== TEST 2: Auth0 client environment variables are set
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
--- config
  location = /t {
    content_by_lua_block {
      ngx.print(os.getenv('AUTH0_CLIENT_ID') == nil or os.getenv('AUTH0_CLIENT_SECRET') == nil)
    }
  }
--- request
GET /t
--- response_body
false
