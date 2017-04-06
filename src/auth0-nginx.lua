local jwt = require('resty.jwt')
local validators = require('resty.jwt-validators')
local id = os.getenv('AUTH0_APIKEY_ID')
local secret = os.getenv('AUTH0_APIKEY_SECRET')
local appHref = os.getenv('AUTH0_CLIENT_HREF')

assert(id ~= nil, 'Environment variable AUTH0_APIKEY_ID not set')
assert(secret ~= nil, 'Environment variable AUTH0_APIKEY_SECRET not set')

local M = {}
local Helpers = {}

function M.getAccount()
  getAccount(false)
end

function M.requireAccount()
  getAccount(true)
end

function getAccount(required)
  local jwtString = Helpers.getBearerToken()

  if not jwtString then
    return Helpers.exit(required)
  end

  local claimSpec = {
    exp = validators.required(validators.opt_is_not_expired()),
  }

  local jwt = jwt:verify(secret, jwtString, claimSpec)

  if not (jwt.verified and jwt.header.stt == 'access' and jwt.header.alg == 'HS256') then
    return Helpers.exit(required)
  end
end


local http = require('resty.http')
local cjson = require('cjson')

function M.oauthTokenEndpoint(applicationHref)
  applicationHref = applicationHref or appHref
  oauthTokenEndpoint(applicationHref)
end

function oauthTokenEndpoint(applicationHref)
  local httpc = http.new()
  ngx.req.read_body()

  local headers = ngx.req.get_headers()
  local body = ngx.req.get_body_data()
  local cbody = nil

  ngx.print(body)
  -- Proxy these certain parameters to the Auth0 API
  -- Only support 'client_credentials' and 'password' flows

  -- Password flow
  if body['grant_type'] == 'password' then
      cbody = {
          ['grant_type'] = body['grant_type'],
          username = body['username'],
          password = body['password'],
          audience = 'null',
          ['client_id'] = id,
          ['client_secret'] = secret
      }
  else
  -- Client Credentials flow
      cbody = body
  end

  local request = {
    method = ngx.var.request_method,
    body = cbody,
    headers = {
      ['content-type'] = 'application/json',
      accept = 'application/json'
    }
  }

  -- Make the request

  local res, err = httpc:request_uri(applicationHref .. '/oauth/token' , request)

  if not res or res.status >= 500 then
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  local json = cjson.decode(res.body)
  local response = {}

  -- Respond with a stripped token response or error

  if res.status == 200 then
    response = {
      access_token = json.access_token,
      refresh_token = json.refresh_token,
      token_type = json.token_type,
      expires_in = json.expires_in
    }
  else
    response = {
      error = json.error,
      message = json.message
    }
  end

  ngx.status = res.status
  ngx.header.content_type = res.headers['Content-Type']
  ngx.header.cache_control = 'no-store'
  ngx.header.pragma = 'no-cache'
  ngx.say(cjson.encode(response))
  ngx.exit(ngx.HTTP_OK)
end

function Helpers.exit(required)
  if required then
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
  else
    return ngx.exit(ngx.OK)
  end
end

function Helpers.getBearerToken()
  local authorizationHeader = ngx.var.http_authorization

  if not authorizationHeader or not authorizationHeader:startsWith('Bearer ') then
    return nil
  else
    return authorizationHeader:sub(8)
  end
end

function Helpers.getBasicAuthCredentials()
  local authorizationHeader = ngx.var.http_authorization

  if not authorizationHeader or not authorizationHeader:startsWith('Basic ') then
    return nil
  else
    local decodedHeader = ngx.decode_base64(authorizationHeader:sub(7))
    local position = decodedHeader:find(':')
    local username = decodedHeader:sub(1,position-1)
    local password = decodedHeader:sub(position+1)

    return username, password
  end
end

function string:startsWith(partialString)
  local partialStringLength = partialString:len()
  return self:len() >= partialStringLength and self:sub(1, partialStringLength) == partialString
end

function Helpers.copy(headers)
  local result = {}
  for k,v in pairs(headers) do
    result[k] = v
  end
  return result
end

return M
