use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.getAccount passes through with no auth header
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
--- config
    location = /t {
        access_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.getAccount()
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- response_body
Authorization: 


=== TEST 2: auth0.getAccount passes through with invalid JWT
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
--- config
    location = /t {
        access_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.getAccount()
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- more_headers
Authorization: Bearer BADTOKEN
--- response_body
Authorization: Bearer BADTOKEN



=== TEST 3: auth0.getAccount passes header on valid JWT
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env API1_AUD;
env API1_KEY;
--- config
    location = /t {
        access_by_lua_block {
            local jwt = require('resty.jwt')
            local testJwtContents = {
                header = {
                    alg = 'HS256',
                    typ = 'JWT'
                },
                payload = {
                    exp = ngx.time() + 3600,
                    iat = ngx.time() - 5,
                    iss = os.getenv('AUTH0_ACCOUNT_DOMAIN'),
                    aud = os.getenv('API1_AUD')
                }
            }
            
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

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            local idToken = jwt:sign(os.getenv('AUTH0_CLIENT_SECRET'), testIdContents)
            ngx.req.set_header('authorization', 'Bearer ' .. accessToken)
            ngx.req.set_header('x-auth0-account-token', idToken)

            local auth0 = require('auth0-nginx')
            auth0.getAccount(os.getenv('API1_KEY'), os.getenv('API1_AUD'))
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
            ngx.say('X-Auth0-Account: ' .. (ngx.var.http_x_auth0_account or ''))
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body_like
Authorization: Bearer (.*)
X-Auth0-Account: {(.*)}
