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
  local auth = jwt:load_jwt(jwtString)

  if not jwtString or not auth.valid then
    return Helpers.exit(required)
  end

  local claimSpec = {
    exp = validators.required(validators.opt_is_not_expired()),
    iss = validators.required(validators.opt_equals(applicationHref)),
    aud = validators.required(validators.opt_equals(audience))
  }
  if type(auth.payload.aud) == 'table' then
    claimSpec.aud = validators.required(
      validators.opt_check(audience, Helpers.checkAud, 'check_aud', 'table'))
  end

  local checkedJwt = jwt:verify(secret, jwtString, claimSpec)
  if not (checkedJwt.verified and checkedJwt.header.alg == 'HS256') then
    return Helpers.exit(required)
  end

  local accountToken = Helpers.getAccountToken()
  local account = jwt:load_jwt(accountToken).payload
  if account then
    ngx.req.set_header('x-auth0-account', cjson.encode(account))
  end
end

function M.changePassword(applicationHref)
  applicationHref = applicationHref or appHref
  ngx.req.read_body()

  local httpc = http.new()
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

  local response = res.body
  Helpers.finish(res, response)
end

function M.signup(applicationHref)
  applicationHref = applicationHref or appHref
  ngx.req.read_body()

  local httpc = http.new()
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

function M.socialOauthTokenEndpoint(verify, includeUser, applicationHref)
  applicationHref = applicationHref or appHref
  includeUser = includeUser or false
  verify = verify or false

  ngx.req.read_body()
  local body = cjson.decode(ngx.req.get_body_data())
  local headers = ngx.req.get_headers()
  local httpc = http.new()

  -- Add clientId and clientSecret

  body['client_id'] = clientId
  body['client_secret'] = clientSecret

  -- Build and send the token grant request

  local request = Helpers.buildRequest(headers, body)
  local res, err = httpc:request_uri(applicationHref .. 'oauth/token' , request)
  if not res or res.status >= 500 then
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  --Build and send the userinfo request

  local authRes = cjson.decode(res.body)
  local userinfoHeaders = {
    Authorization = 'Bearer ' .. authRes['access_token']
  }
  local userinfoRequest = Helpers.buildRequest(userinfoHeaders)
  local userinfoRes, userinfoErr = httpc:request_uri(applicationHref .. 'userinfo', userinfoRequest)
  if not userinfoRes or userinfoRes.status >= 500 then
    return ngx.exit(ngx.HTTP_INTERNAL_SERVER_ERROR)
  end

  -- Verify email if enabled

  local userinfoBody = cjson.decode(userinfoRes.body)
  if verify then
    local email = userinfoBody['email']
    Helpers.checkDomainWhitelist(email)
  end

  -- Finish request

  local responseBody = authRes
  if includeUser then
    responseBody = {
      auth = authRes,
      user = userinfoBody
    }
  end
  Helpers.finish(res, responseBody)
end

function M.oauthTokenEndpoint(includeUser, applicationHref)
  applicationHref = applicationHref or appHref
  includeUser = includeUser or false

  ngx.req.read_body()
  local body = cjson.decode(ngx.req.get_body_data())
  local headers = ngx.req.get_headers()
  local httpc = http.new()

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
  local authRes = cjson.decode(res.body)

  -- Finish the request

  local responseBody = authRes
  if includeUser and body['grant_type'] == 'password' then
    --Build and send the userinfo request
    local idToken = authRes['id_token']
    local userMeta = jwt:load_jwt(idToken).payload
    responseBody = {
      auth = authRes,
      user = userMeta
    }
  end
  Helpers.finish(res, responseBody)
end

function M.socialLogin(applicationHref)
  applicationHref = applicationHref or appHref

  -- Attach client_id; Redirect

  if not ngx.var.args then
    ngx.exit(ngx.HTTP_BAD_REQUEST)
  end

  local ep = applicationHref .. 'authorize?' .. ngx.var.args .. '&client_id=' .. clientId
  return ngx.redirect(ep)
end

function M.verifyAccount(applicationHref)
  applicationHref = applicationHref or appHref

  local accountToken = Helpers.getAccountToken()
  local account = jwt:load_jwt(accountToken).payload
  if account then
    local email = account['email']
    Helpers.checkDomainWhitelist(email)
  else
    return ngx.exit(ngx.HTTP_BAD_REQUEST)
  end
end

function Helpers.finish(res, response)
  ngx.status = res.status
  ngx.header.content_type = res.headers['Content-Type']
  ngx.header.cache_control = 'no-store'
  ngx.header.pragma = 'no-cache'
  ngx.say(cjson.encode(response))
  ngx.exit(ngx.HTTP_OK)
end

function Helpers.checkAud(val, check_val)
  for k,v in pairs(val) do
    if v == check_val then return true end
  end
  return false
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
  local req = {
    method = method or ngx.var.request_method,
  }

  if headers then
    req['headers'] = {
      ['Content-Type'] = headers['Content-Type'],
      accept = 'application/json'
    }

    if headers['Authorization'] then
      req['headers']['Authorization'] = headers['Authorization']
    end
  end

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

function Helpers.getAccountToken()
  local accountTokenHeader = ngx.var.http_x_auth0_account_token

  if not accountTokenHeader then
    return nil
  else
    return accountTokenHeader
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

return M
