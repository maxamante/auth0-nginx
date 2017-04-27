use Test::Nginx::Socket 'no_plan';
run_tests();

__DATA__

=== TEST 1: auth0.requireAccount 401s with no auth header
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
--- config
    location = /t {
        access_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.requireAccount()
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 401


=== TEST 2: auth0.requireAccount 401s with invalid JWT
--- main_config
env AUTH0_CLIENT_ID;
env AUTH0_CLIENT_SECRET;
--- config
    location = /t {
        access_by_lua_block {
            local auth0 = require('auth0-nginx')
            auth0.requireAccount()
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- more_headers
Authorization: Bearer BADTOKEN
--- error_code: 401


=== TEST 3: auth0.requireAccount 401s with jwt without exp
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
                    iat = ngx.time() - 5,
                    iss = os.getenv('AUTH0_ACCOUNT_DOMAIN'),
                    aud = os.getenv('API1_AUD')
                }
            }

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            ngx.req.set_header('authorization', 'Bearer ' .. accessToken)

            local auth0 = require('auth0-nginx')
            auth0.requireAccount(os.getenv('API1_KEY'), os.getenv('API1_AUD'))
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 401


=== TEST 4: auth0.requireAccount 401s with jwt without iss
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
                    iat = ngx.time() - 5,
                    exp = ngx.time() + 3600,
                    aud = os.getenv('API1_AUD')
                }
            }

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            ngx.req.set_header('authorization', 'Bearer ' .. accessToken)

            local auth0 = require('auth0-nginx')
            auth0.requireAccount(os.getenv('API1_KEY'), os.getenv('API1_AUD'))
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 401


=== TEST 5: auth0.requireAccount 401s with jwt without aud
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
                    iat = ngx.time() - 5,
                    exp = ngx.time() + 3600,
                    iss = os.getenv('AUTH0_ACCOUNT_DOMAIN')
                }
            }

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            ngx.req.set_header('authorization', 'Bearer ' .. accessToken)

            local auth0 = require('auth0-nginx')
            auth0.requireAccount(os.getenv('API1_KEY'), os.getenv('API1_AUD'))
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 401


=== TEST 6: auth0.requireAccount 401s with jwt with wrong signing key
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
                    iat = ngx.time() - 5,
                    exp = ngx.time() + 3600,
                    iss = os.getenv('AUTH0_ACCOUNT_DOMAIN'),
                    aud = os.getenv('API1_AUD')
                }
            }

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            ngx.req.set_header('authorization', 'Bearer ' .. accessToken)

            local auth0 = require('auth0-nginx')
            auth0.requireAccount('WRONGKEY', os.getenv('API1_AUD'))
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 401


=== TEST 7: auth0.requireAccount 401s with jwt with wrong audience
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
                    iat = ngx.time() - 5,
                    exp = ngx.time() + 3600,
                    iss = os.getenv('AUTH0_ACCOUNT_DOMAIN'),
                    aud = os.getenv('API1_AUD')
                }
            }

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            ngx.req.set_header('authorization', 'Bearer ' .. accessToken)

            local auth0 = require('auth0-nginx')
            auth0.requireAccount(os.getenv('API1_KEY'), 'WRONGAUDIENCE')
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 401


=== TEST 8: auth0.requireAccount 500s with an unsupported alg
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
                    alg = 'RS256',
                    typ = 'JWT'
                },
                payload = {
                    iat = ngx.time() - 5,
                    exp = ngx.time() + 3600,
                    iss = os.getenv('AUTH0_ACCOUNT_DOMAIN'),
                    aud = os.getenv('API1_AUD')
                }
            }

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            ngx.req.set_header('Authorization', 'Bearer ' .. accessToken)

            local auth0 = require('auth0-nginx')
            auth0.requireAccount(os.getenv('API1_KEY'), os.getenv('API1_AUD'))
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 500


=== TEST 9: auth0.requireAccount passes headers on valid JWT
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
                    iat = ngx.time() - 5,
                    exp = ngx.time() + 3600,
                    iss = os.getenv('AUTH0_ACCOUNT_DOMAIN'),
                    aud = os.getenv('API1_AUD')
                }
            }

            local accessToken = jwt:sign(os.getenv('API1_KEY'), testJwtContents)
            ngx.req.set_header('Authorization', 'Bearer ' .. accessToken)

            local auth0 = require('auth0-nginx')
            auth0.requireAccount(os.getenv('API1_KEY'), os.getenv('API1_AUD'))
        }
        content_by_lua_block {
            ngx.say('Authorization: ' .. (ngx.var.http_authorization or ''))
        }
    }
--- request
GET /t
--- error_code: 200
--- response_body_like
Authorization: Bearer (.*)
