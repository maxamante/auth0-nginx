package = 'auth0-nginx'
version = '1.5.0-0'
source = {
  url = 'git://github.com/maxamante/auth0-nginx',
  tag = '1.5.0'
}
description = {
  summary = 'An Auth0 + nginx integration',
  detailed = [[
    Use Nginx as an API Gateway for your Auth0 applications.
  ]],
  homepage = 'https://auth0.com/',
  license = 'Apache2'
}
dependencies = {
  'lua >= 5.1',
  'lua-resty-jwt = 0.1.5',
  'lua-resty-http = 0.08'
}
build = {
  type = 'builtin',
  modules = {
    ['auth0-nginx'] = 'src/auth0-nginx.lua',
  }
}
