use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.verifyAccount 400s when an X-Auth0-Account-Token is not present
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.verifyAccount()
        }
    }
--- request
GET /t
--- error_code: 400


=== TEST 2: auth0.verifyAccount 412s when a blacklisted domain is used to login
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
env API1_KEY;
--- config
    location = /t {
        access_by_lua_block {
            local jwt = require('resty.jwt')
            local testIdContents = {
                header = {
                    alg = 'HS256',
                    typ = 'JWT'
                },
                payload = {
                    email = 'test.email@blacklisted.com',
                    name = 'test.email@blacklisted.com',
                    email_verified = false
                }
            }
            
            local idToken = jwt:sign(os.getenv('API1_KEY'), testIdContents)
            ngx.req.set_header('x-auth0-account-token', idToken)
        }
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.verifyAccount()
        }
    }
--- request
GET /t
--- error_code: 412


=== TEST 3: auth0.verifyAccount 200s when a whitelisted domain is used to login
For this test to pass you must include `example.com` in your AUTH0_WHITELIST_DOMAINS variable
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
env API1_KEY;
--- config
    location = /t {
        access_by_lua_block {
            local jwt = require('resty.jwt')
            local testIdContents = {
                header = {
                    alg = 'HS256',
                    typ = 'JWT'
                },
                payload = {
                    email = 'test.email@example.com',
                    name = 'test.email@example.com',
                    email_verified = false
                }
            }
            
            local idToken = jwt:sign(os.getenv('API1_KEY'), testIdContents)
            ngx.req.set_header('x-auth0-account-token', idToken)
        }
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.verifyAccount()
        }
    }
--- request
GET /t
--- error_code: 200
