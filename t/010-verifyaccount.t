use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.verifyAccount 400s when there's no account
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.verifyAccount('http://127.0.0.1:19232/mock/')
        }
    }
--- more_headers
Content-type: application/json
--- request
GET /t
--- ignore_response_body
--- error_code: 400


=== TEST 2: auth0.verifyAccount 412s when domain not whitelisted
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.verifyAccount('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
X-Auth0-Account-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJ0ZXN0LXVzZXJAbm90YWxsb3dlZC5jb20iLCJqdGkiOiI2ZDI2NWY1Mi0xNzNkLTRkZjUtOTVlOC1kYTdlMDRjM2FkM2UiLCJpYXQiOjE1MTY3NTQ3NDUsImV4cCI6MTUxNjc1ODM0NX0.G3aBMUTWBdiOo2FwpmugviIYpQ9TeEulem5DFMth1uc
--- request
GET /t
--- ignore_response_body
--- error_code: 412


=== TEST 3: auth0.verifyAccount happy path
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
env AUTH0_ACCOUNT_DOMAIN;
env AUTH0_WHITELIST_DOMAINS;
--- config
    location = /t {
        content_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.verifyAccount('http://127.0.0.1:1984/mock/')
        }
    }
--- more_headers
Content-type: application/json
X-Auth0-Account-Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZSwiZW1haWwiOiJ0ZXN0LXVzZXJAZXhhbXBsZS5jb20iLCJqdGkiOiI4OTIxYjU0NC1jMWY0LTQwYTYtOGRjMi1mNDJiZWU4MzEzODkiLCJpYXQiOjE1MTY3NTQ3ODIsImV4cCI6MTUxNjc1ODM4Mn0.4TWo0FrTxkgTzRvFRdWGXx8ZVqRO3tF1OGMI2sR8LnY
--- request
GET /t
--- ignore_response_body
--- error_code: 200
