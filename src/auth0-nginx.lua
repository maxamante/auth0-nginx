local cjson = require('cjson')
local http = require('resty.http')
local jwt = require('resty.jwt')
local validators = require('resty.jwt-validators')

local appHref = os.getenv('AUTH0_ACCOUNT_DOMAIN')
local clientId = os.getenv('AUTH0_CLIENT_ID')
local clientSecret = os.getenv('AUTH0_CLIENT_SECRET')
local connection = os.getenv('AUTH0_CLIENT_CONNECTION')
local whitelistDomains = os.getenv('AUTH0_WHITELIST_DOMAINS')

assert(clientId ~= nil, 'Environment variable AUTH0_CLIENT_ID not set')
assert(clientSecret ~= nil, 'Environment variable AUTH0_CLIENT_SECRET not set')

local M = {}
local Helpers = {}

function M.getAccount(secret, aud, applicationHref)
  applicationHref = applicationHref or appHref
  getAccount(false, secret, aud, applicationHref)
end

function M.requireAccount(secret, aud, applicationHref)
  applicationHref = applicationHref or appHref
  getAccount(true, secret, aud, applicationHref)
end

function getAccount(required, secret, audience, applicationHref)
  local jwtString = Helpers.getBearerToken()

  if not jwtString then
    return Helpers.exit(required)
  end

  local claimSpec = {
    exp = validators.required(validators.opt_is_not_expired()),
    iss = validators.required(validators.opt_equals(applicationHref)),
    aud = validators.required(validators.opt_equals(audience)),
  }

  local jwt = jwt:verify(secret, jwtString, claimSpec)

  if not (jwt.verified and jwt.header.alg == 'HS256') then
    return Helpers.exit(required)
  end
end

function M.changePassword(applicationHref)
  applicationHref = applicationHref or appHref
  changePassword(applicationHref)
end

function changePassword(applicationHref)
  local httpc = http.new()
  ngx.req.read_body()

  local headers = ngx.req.get_headers()
  local body = cjson.decode(ngx.req.get_body_data())

  -- Add clientId and connection

  body['client_id'] = clientId
  body['connection'] = connection

  -- Build and send the request

  local request = Helpers.buildRequest(headers, body)
  local res, err = httpc:request_uri(applicationHref .. 'dbconnections/change_password', request)
  if not res or res.status >= 500 then
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  -- Finish the request

  local response = cjson.decode(res.body)
  Helpers.finish(res, response)
end

function M.signup(applicationHref)
  applicationHref = applicationHref or appHref
  signup(applicationHref)
end

function signup(applicationHref)
  local httpc = http.new()
  ngx.req.read_body()

  local headers = ngx.req.get_headers()
  local body = cjson.decode(ngx.req.get_body_data())

  -- Add clientId and connection

  body['client_id'] = clientId
  body['connection'] = connection

  -- Validate email being registered

  local email = body['email']
  Helpers.checkDomainWhitelist(email)

  -- Build and send the request

  local request = Helpers.buildRequest(headers, body)
  local res, err = httpc:request_uri(applicationHref .. 'dbconnections/signup', request)
  if not res or res.status >= 500 then
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  -- Parse the response

  local names = {
    "_id",
    "email_verified",
    "email"
  }
  local response = Helpers.parseResponse(res, names)

  -- Finish the request

  Helpers.finish(res, response)
end

function M.oauthTokenEndpoint(applicationHref)
  applicationHref = applicationHref or appHref
  oauthTokenEndpoint(applicationHref)
end

function oauthTokenEndpoint(applicationHref)
  local httpc = http.new()
  ngx.req.read_body()

  local headers = ngx.req.get_headers()
  local body = cjson.decode(ngx.req.get_body_data())

  -- Add clientId and clientSecret to non-client_credentials requests

  if body['grant_type'] ~= 'client_credentials' then
    body['client_id'] = clientId
    body['client_secret'] = clientSecret
  end

  -- Build the request

  local request = Helpers.buildRequest(headers, body)
  local res, err = httpc:request_uri(applicationHref .. 'oauth/token' , request)
  if not res or res.status >= 500 then
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  -- Parse the response

  local names = {
    "access_token",
    "refresh_token",
    "token_type",
    "expires_in"
  }
  local response = Helpers.parseResponse(res, names)

  -- Finish the request

  Helpers.finish(res, response)
end

function M.socialLogin(applicationHref)
  applicationHref = applicationHref or appHref
  socialLogin(applicationHref)
end

function socialLogin(applicationHref)
  local httpc = http.new()
  ngx.req.read_body()

  -- Attach client_id; Redirect

  local ep = applicationHref .. 'authorize?' .. ngx.var.args .. '&client_id=' .. clientId
  return ngx.redirect(ep)
end

function M.userInfo(applicationHref, checkDomain)
  applicationHref = applicationHref or appHref
  userInfo(applicationHref, checkDomain)
end

function userInfo(applicationHref, checkDomain)
  local httpc = http.new()
  ngx.req.read_body()

  local headers = ngx.req.get_headers()
  local request = Helpers.buildRequest(headers)
  local res, err = httpc:request_uri(applicationHref .. 'userinfo', request)
  if not res or res.status >= 500 then
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  -- Parse the response

  local body = cjson.decode(res.body)
  local email = body['email']
  if checkDomain then
    Helpers.checkDomainWhitelist(email)
  end

  -- Finish the request

  local response = res.body
  Helpers.finish(res, response)
end

function Helpers.finish(res, response)
  ngx.status = res.status
  ngx.header.content_type = res.headers['Content-Type']
  ngx.header.cache_control = 'no-store'
  ngx.header.pragma = 'no-cache'
  ngx.say(cjson.encode(response))
  ngx.exit(ngx.HTTP_OK)
end

function Helpers.checkDomainWhitelist(email)
  local whitelist = Helpers.explode(',', whitelistDomains)
  if whitelist then
    local origin = email:split('@')[2]
    if whitelist[origin] == nil then
      return ngx.exit(412)
    end
  end
end

function Helpers.parseResponse(res, responseNames)
  local json = cjson.decode(res.body)
  local response = {}

  -- Parse out a stripped response or error

  if res.status == 200 then
    for k,v in pairs(responseNames) do
      response[v] = json[v]
    end
  else
    response = {
      error = json.error,
      message = json.message,
      description = json.description
    }
  end

  return response
end

function Helpers.buildRequest(headers, body, method)
  headers['accept'] = 'application/json'
  local req = {
    method = method or ngx.var.request_method,
    headers = headers
  }
  if body then
    req['body'] = cjson.encode(body)
  end
  return req
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

function string:split(sSeparator, nMax, bRegexp)
   assert(sSeparator ~= '')
   assert(nMax == nil or nMax >= 1)

   local aRecord = {}

   if self:len() > 0 then
      local bPlain = not bRegexp
      nMax = nMax or -1

      local nField, nStart = 1, 1
      local nFirst,nLast = self:find(sSeparator, nStart, bPlain)
      while nFirst and nMax ~= 0 do
         aRecord[nField] = self:sub(nStart, nFirst-1)
         nField = nField+1
         nStart = nLast+1
         nFirst,nLast = self:find(sSeparator, nStart, bPlain)
         nMax = nMax-1
      end
      aRecord[nField] = self:sub(nStart)
   end

   return aRecord
end

function Helpers.explode(div, str)
    if (div == '') then return false end
    if (str == nil) then return false end
    local pos, arr = 0, {}
    -- for each divider found
    for st, sp in function() return string.find(str,div,pos,true) end do
      arr[string.sub(str,pos,st-1)] = string.sub(str,pos,st-1)
      pos = sp + 1 -- Jump past current divider
    end
    arr[string.sub(str,pos)] = string.sub(str,pos)
    return arr
end

return M
