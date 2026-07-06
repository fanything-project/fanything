local base64 = require "base64"
local nmap = require "nmap"
local openssl = require "openssl"
local shortport = require "shortport"
local sslcert = require "sslcert"
local sslv2 = require "sslv2"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local tls = require "tls"

description = [[
Extracts FAN/1 fingerprints from live TLS services.

The output mirrors fanfp.py fields: mode, protocol, role, fingerprint, features,
sha256, and flow. Probes run TLSv1.3, TLSv1.2, TLSv1.1, TLSv1.0, SSLv3, then
SSLv2, stopping at the first full server fingerprint.
]]

---
-- @usage
-- nmap -sV --script ./fanything-tls.nse <target>
--
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | fanything-tls:
-- |   protocol: tls
-- |   role: server
-- |   fingerprint: fan1:tls:server:active:...
-- |   features: tls|server|v=771|c=4865|e=43-51|sv=772
-- |   sha256: ...
-- |   flow:
-- |     src: 192.0.2.10
-- |     sport: 22
-- |     dst: 198.51.100.5
-- |_    dport: 22
--
-- @args fanything-tls.timeout Socket timeout in milliseconds. Default: 5000.
-- @args fanything-tls.tls-version Force TLS protocol version: TLSv1.3, TLSv1.2,
-- TLSv1.1, TLSv1.0, SSLv3, or SSLv2. Default: probe TLSv1.3, TLSv1.2,
-- TLSv1.1, TLSv1.0, SSLv3, then SSLv2 and stop at first full success.
-- @args fanything-tls.force Run on any open TCP port. Useful for tests on high
-- local ports.

author = "FAN/1 contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  if port.protocol ~= "tcp" or port.state ~= "open" then
    return false
  end
  if stdnse.get_script_args(SCRIPT_NAME .. ".force") then
    return true
  end
  return shortport.port_or_service({443, 465, 636, 853, 993, 995, 8443, 9443},
    {"ssl", "https", "imaps", "pop3s", "smtps", "ldaps"}, "tcp", "open")(host, port)
    or sslcert.getPrepareTLSWithoutReconnect(port) ~= nil
end

local function timeout()
  return tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5000
end

-- TLS 1.3 cipher order derived from the current Firefox LTS/ESR 140 branch
-- (latest ESR point release documented by Mozilla as 140.12.0 when checked on
-- 2026-06-18) and NSS SSL_ImplementedCiphers[] in mozilla-esr140.
-- The script keeps a protocol-named table; Firefox is only the source
-- reference for the order.
local TLS13_CIPHERS = {
  "TLS_AKE_WITH_AES_128_GCM_SHA256",
  "TLS_AKE_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_AKE_WITH_AES_256_GCM_SHA384",
}
-- TLS 1.2 cipher order derived from the same Firefox ESR 140 / NSS enabled
-- security.ssl3.* prefs and SSL_ImplementedCiphers[] order.
local TLS12_CIPHERS = {
  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
  "TLS_RSA_WITH_AES_128_GCM_SHA256",
  "TLS_RSA_WITH_AES_256_GCM_SHA384",
  "TLS_RSA_WITH_AES_128_CBC_SHA",
  "TLS_RSA_WITH_AES_256_CBC_SHA",
}

-- TLS 1.1, TLS 1.0, and SSLv3 cipher order derived from Firefox 33-era NSS:
-- security/manager/ssl/src/nsNSSComponent.cpp sCipherPrefs enabledByDefault
-- entries, ordered by security/nss/lib/ssl/sslenum.c.
local LEGACY_CIPHERS = {
  "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
  "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
  "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
  "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
  "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
  "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
  "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
  "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
  "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
  "TLS_RSA_WITH_AES_128_CBC_SHA",
  "TLS_RSA_WITH_AES_256_CBC_SHA",
  "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
  "TLS_RSA_WITH_RC4_128_SHA",
  "TLS_RSA_WITH_RC4_128_MD5",
}

-- SSLv2 is not calibrated to Firefox here. The active probe uses
-- Nmap's SSLv2 library cipher names for old-server measurement only.
local SSLV2_CIPHERS = {
  "SSL2_RC4_128_WITH_MD5",
  "SSL2_RC4_128_EXPORT40_WITH_MD5",
  "SSL2_RC2_128_CBC_WITH_MD5",
  "SSL2_RC2_128_CBC_EXPORT40_WITH_MD5",
  "SSL2_IDEA_128_CBC_WITH_MD5",
  "SSL2_DES_64_CBC_WITH_MD5",
  "SSL2_DES_192_EDE3_CBC_WITH_MD5",
}

local function tls_versions()
  local forced = stdnse.get_script_args(SCRIPT_NAME .. ".tls-version")
  if forced == "TLSv1.3" or forced == "TLSv1.2" or forced == "TLSv1.1"
      or forced == "TLSv1.0" or forced == "SSLv3" or forced == "SSLv2" then
    return {forced}
  end
  return {"TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0", "SSLv3", "SSLv2"}
end

local function base64url(s)
  return (base64.enc(s):gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

local function fan1(protocol, role, mode, features)
  local digest = stdnse.tohex(openssl.digest("sha256", features))
  return ("fan1:%s:%s:%s:%s:sha256:%s"):format(protocol, role, mode, base64url(features), digest), digest
end

local function is_grease(v)
  return (v & 0x0f0f) == 0x0a0a and (v & 0x00ff) == ((v >> 8) & 0x00ff)
end

local TLS_SERVER_HELLO_VOLATILE_EXTENSIONS = { [0] = true, [11] = true, [35] = true }

local function is_stable_server_hello_extension(v)
  return not is_grease(v) and not TLS_SERVER_HELLO_VOLATILE_EXTENSIONS[v]
end

local function join_ints(values, filter_grease)
  local out = {}
  for _, v in ipairs(values) do
    if not (filter_grease and is_grease(v)) then
      out[#out + 1] = tostring(v)
    end
  end
  return table.concat(out, "-")
end

local function u16(s, i)
  local a, b = s:byte(i, i + 1)
  if not a or not b then return nil end
  return a * 256 + b
end

local function read_vec(s, i, len_size)
  if i + len_size - 1 > #s then return nil end
  local len = 0
  for p = i, i + len_size - 1 do
    len = len * 256 + s:byte(p)
  end
  i = i + len_size
  if i + len - 1 > #s then return nil end
  return s:sub(i, i + len - 1), i + len
end

local function u16_list(s)
  local out = {}
  for i = 1, #s - 1, 2 do
    out[#out + 1] = u16(s, i)
  end
  return out
end

local function tls_server_features_from_raw(response)
  local off = 1
  while off + 4 <= #response do
    local content_type = response:byte(off)
    local rec_len = u16(response, off + 3)
    local record = response:sub(off + 5, off + 4 + rec_len)
    off = off + 5 + rec_len

    if content_type == 22 and #record >= 4 and record:byte(1) == 2 then
      local hs_len = record:byte(2) * 65536 + record:byte(3) * 256 + record:byte(4)
      local body = record:sub(5, 4 + hs_len)
      if #body < 38 then return nil end

      local version = u16(body, 1)
      local i = 35
      local _, next_i = read_vec(body, i, 1)
      if not next_i or next_i + 2 > #body then return nil end
      i = next_i
      local cipher = u16(body, i)
      i = i + 3

      local ext_types, selected_version = {}, ""
      if i <= #body then
        local ext_blob
        ext_blob, i = read_vec(body, i, 2)
        if ext_blob then
          local eo = 1
          while eo + 3 <= #ext_blob do
            local et = u16(ext_blob, eo)
            local el = u16(ext_blob, eo + 2)
            local ed = ext_blob:sub(eo + 4, eo + 3 + el)
            eo = eo + 4 + el
            if is_stable_server_hello_extension(et) then ext_types[#ext_types + 1] = et end
            if et == 43 and #ed == 2 then selected_version = tostring(u16(ed, 1)) end
          end
        end
      end

      return ("tls|server|v=%d|c=%d|e=%s|sv=%s"):format(
        version, cipher, join_ints(ext_types, false), selected_version)
    end
  end
  return nil
end

local function socket_flow(sock, fallback_host, fallback_port)
  local flow = {
    src = fallback_host and fallback_host.ip or "",
    sport = fallback_port and fallback_port.number or "",
    dst = "",
    dport = "",
  }

  local ok, lhost, lport, rhost, rport = pcall(function()
    local status, local_host, local_port, remote_host, remote_port = sock:get_info()
    if not status then return nil end
    return local_host, local_port, remote_host, remote_port
  end)
  if ok and lhost then
    flow.src = rhost or flow.src
    flow.sport = rport or flow.sport
    flow.dst = lhost or ""
    flow.dport = lport or ""
  end

  return flow
end

local function build_tls_extensions(host, version)
  local extensions = {
    elliptic_curves =
      tls.EXTENSION_HELPERS.elliptic_curves({"ecdh_x25519", "secp256r1", "secp384r1", "secp521r1"}),
    ec_point_formats = tls.EXTENSION_HELPERS.ec_point_formats({"uncompressed"}),
    application_layer_protocol_negotiation =
      tls.EXTENSION_HELPERS.application_layer_protocol_negotiation({"h2", "http/1.1"}),
  }
  local name = tls.servername(host) or host.targetname or host.name
  if name and not name:match("^%d+%.%d+%.%d+%.%d+$") then
    extensions.server_name = tls.EXTENSION_HELPERS.server_name(name)
  end
  if version == "TLSv1.3" then
    extensions.signature_algorithms_13 =
      tls.EXTENSION_HELPERS.signature_algorithms_13({
        "rsa_pss_rsae_sha256",
        "rsa_pss_rsae_sha384",
        "ecdsa_secp256r1_sha256",
        "ecdsa_secp384r1_sha384",
        "rsa_pkcs1_sha256",
        "rsa_pkcs1_sha384",
      })
    extensions.supported_versions =
      tls.EXTENSION_HELPERS.supported_versions({"TLSv1.3", "TLSv1.2"})
    local x25519_basepoint = string.char(9) .. string.rep("\0", 31)
    extensions.key_share = string.pack(">s2", string.pack(">I2s2", 29, x25519_basepoint))
  elseif version == "TLSv1.2" then
    extensions.signature_algorithms =
      tls.EXTENSION_HELPERS.signature_algorithms({
        {"sha256", "rsa"},
        {"sha256", "ecdsa"},
        {"sha384", "rsa"},
        {"sha384", "ecdsa"},
        {"sha1", "rsa"},
      })
  end
  return extensions
end

local function ciphers_for_version(version)
  if version == "TLSv1.3" then
    local ciphers = {}
    for _, c in ipairs(TLS13_CIPHERS) do ciphers[#ciphers + 1] = c end
    for _, c in ipairs(TLS12_CIPHERS) do ciphers[#ciphers + 1] = c end
    return ciphers
  elseif version == "TLSv1.2" then
    return TLS12_CIPHERS
  end
  return LEGACY_CIPHERS
end

local function get_tls_response(host, port, version)
  local ciphers = ciphers_for_version(version)
  if not ciphers then return nil end

  local hello = tls.client_hello({
    protocol = version,
    record_protocol = version,
    ciphers = ciphers,
    extensions = build_tls_extensions(host, version),
  })

  local sock, status, err
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, sock = specialized(host, port)
    if not status then return nil end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout())
    status, err = sock:connect(host, port)
    if not status then return nil end
  end
  sock:set_timeout(timeout())
  status, err = sock:send(hello)
  if not status then sock:close(); return nil end
  local flow = socket_flow(sock, host, port)
  status, err = tls.record_buffer(sock)
  sock:close()
  if not status then return nil end
  return err, flow
end

local function sslv2_cipher_code(name)
  local code = sslv2.SSL_CIPHER_CODES[name]
  if not code then return name end
  local a, b, c = code:byte(1, 3)
  return tostring(a * 65536 + b * 256 + c)
end

local function get_sslv2_features(host, port)
  local sock, status, err
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    status, sock = specialized(host, port)
    if not status then return nil end
  else
    sock = nmap.new_socket()
    sock:set_timeout(timeout())
    status, err = sock:connect(host, port)
    if not status then return nil end
  end
  sock:set_timeout(timeout())

  local ok, hello = pcall(sslv2.client_hello, SSLV2_CIPHERS)
  if not ok then sock:close(); return nil end

  status, err = sock:send(hello)
  if not status then sock:close(); return nil end
  local flow = socket_flow(sock, host, port)
  status, err = sslv2.record_buffer(sock)
  sock:close()
  if not status then return nil end

  local _, message = sslv2.record_read(err)
  if not message or message.message_type ~= sslv2.SSL_MESSAGE_TYPES.SERVER_HELLO
      or not message.body or not message.body.ciphers then
    return nil
  end

  local ciphers = {}
  for _, cipher in ipairs(message.body.ciphers) do
    ciphers[#ciphers + 1] = sslv2_cipher_code(cipher)
  end

  return ("tls|server|v=2|c=%s|e=|sv="):format(table.concat(ciphers, "-")), flow
end

local function result(protocol, role, features, flow)
  local mode = "active"
  local fingerprint, digest = fan1(protocol, role, mode, features)
  return {
    mode = mode,
    protocol = protocol,
    role = role,
    fingerprint = fingerprint,
    features = features,
    sha256 = digest,
    flow = flow,
  }
end

action = function(host, port)
  for _, version in ipairs(tls_versions()) do
    if version == "SSLv2" then
      local features, fp_flow = get_sslv2_features(host, port)
      if features then
        return result("tls", "server", features, fp_flow)
      end
    else
      local response, fp_flow = get_tls_response(host, port, version)
      if response then
        local features = tls_server_features_from_raw(response)
        if features then
          return result("tls", "server", features, fp_flow)
        end
      end
    end
  end

  return nil
end
