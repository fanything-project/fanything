local base64 = require "base64"
local nmap = require "nmap"
local openssl = require "openssl"
local rand = require "rand"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Extracts FAN/1 fingerprints from live DTLS services.

The script sends a DTLS ClientHello over UDP, handles HelloVerifyRequest cookie
retry, and fingerprints the responder ServerHello with the same normalized
fields used by fanfp.py for passive DTLS observations.
]]

---
-- @usage
-- nmap -sU --script ./fanything-dtls.nse <target>
--
-- @output
-- PORT     STATE SERVICE
-- 4433/udp open  unknown
-- | fanything-dtls:
-- |   mode: active
-- |   protocol: dtls
-- |   role: server
-- |   fingerprint: fan1:dtls:server:active:...
-- |   features: dtls|server|v=65277|c=53|e=65281-35-15|sv=
-- |   sha256: ...
-- |   flow:
-- |     src: 192.0.2.10
-- |     sport: 4433
-- |     dst: 198.51.100.5
-- |_    dport: 53539
--
-- @args fanything-dtls.timeout Socket timeout in milliseconds. Default: 5000.
-- @args fanything-dtls.dtls-version Force DTLS protocol version: DTLSv1.3,
-- DTLSv1.2, or DTLSv1.0. Default: probe DTLSv1.3, DTLSv1.2, then DTLSv1.0 and
-- stop at first success.
-- @args fanything-dtls.force Run on any open UDP port. Useful for tests.

author = "FAN/1 contributors"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

local TLS_HANDSHAKE = 22
local TLS_CLIENT_HELLO = 1
local TLS_SERVER_HELLO = 2
local DTLS_HELLO_VERIFY_REQUEST = 3

local DTLS_VERSIONS = {
  ["DTLSv1.3"] = 0xfefc,
  ["DTLSv1.2"] = 0xfefd,
  ["DTLSv1.0"] = 0xfeff,
}

-- DTLS active probes use the same modern cipher order as the TLS active
-- scanner: current Firefox LTS/ESR 140 branch (latest ESR point release
-- documented by Mozilla as 140.12.0 when checked on 2026-06-18) and NSS
-- SSL_ImplementedCiphers[] in mozilla-esr140. DTLSv1.3 sends TLS 1.3 suites
-- first, then the TLS 1.2 compatibility list.
local TLS13_CIPHERS = {
  4865, 4867, 4866,
}

local TLS12_CIPHERS = {
  49195, 49199, 52393, 52392, 49196, 49200, 49162, 49161,
  49171, 49172, 156, 157, 47, 53,
}

local LEGACY_CIPHERS = {
  49162, 49161, 49171, 49172, 49159, 49169, 51, 50, 57, 47,
  53, 10, 5, 4,
}

portrule = function(host, port)
  if port.protocol ~= "udp" or port.state == "closed" then
    return false
  end
  if stdnse.get_script_args(SCRIPT_NAME .. ".force") then
    return true
  end
  return shortport.ssl(host, port)
end

local function timeout()
  return tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5000
end

local function dtls_versions()
  local forced = stdnse.get_script_args(SCRIPT_NAME .. ".dtls-version")
  if forced == "DTLSv1.3" or forced == "DTLSv1.2" or forced == "DTLSv1.0" then
    return {forced}
  end
  return {"DTLSv1.3", "DTLSv1.2", "DTLSv1.0"}
end

local function base64url(s)
  return (base64.enc(s):gsub("+", "-"):gsub("/", "_"):gsub("=+$", ""))
end

local function fan1(protocol, role, mode, features)
  local digest = stdnse.tohex(openssl.digest("sha256", features))
  return ("fan1:%s:%s:%s:%s:sha256:%s"):format(protocol, role, mode, base64url(features), digest), digest
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

local function u16(s, i)
  local a, b = s:byte(i, i + 1)
  if not a or not b then return nil end
  return a * 256 + b
end

local function u24(s, i)
  local a, b, c = s:byte(i, i + 2)
  if not a or not b or not c then return nil end
  return a * 65536 + b * 256 + c
end

local function i24(value)
  return string.char((value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff)
end

local function pack_u16_list(values)
  local out = {}
  for _, value in ipairs(values) do
    out[#out + 1] = string.pack(">I2", value)
  end
  return table.concat(out)
end

local function join_ints(values)
  local out = {}
  for _, value in ipairs(values) do
    if not ((value & 0x0f0f) == 0x0a0a and (value & 0x00ff) == ((value >> 8) & 0x00ff)) then
      out[#out + 1] = tostring(value)
    end
  end
  return table.concat(out, "-")
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

local function build_extensions(version_name)
  local extensions = {}
  local groups = pack_u16_list({29, 23, 24, 25})
  extensions[#extensions + 1] = string.pack(">I2s2", 10, string.pack(">s2", groups))
  extensions[#extensions + 1] = string.pack(">I2s2", 11, string.pack(">s1", "\0"))
  extensions[#extensions + 1] = string.pack(">I2s2", 16, string.pack(">s2", string.pack(">s1", "co") .. string.pack(">s1", "http/1.1")))
  if version_name == "DTLSv1.3" then
    local sigs = pack_u16_list({2052, 2053, 1027, 1283, 1025, 1281})
    local versions = pack_u16_list({DTLS_VERSIONS["DTLSv1.3"], DTLS_VERSIONS["DTLSv1.2"]})
    local x25519_basepoint = string.char(9) .. string.rep("\0", 31)
    extensions[#extensions + 1] = string.pack(">I2s2", 13, string.pack(">s2", sigs))
    extensions[#extensions + 1] = string.pack(">I2s2", 43, string.pack(">s1", versions))
    extensions[#extensions + 1] = string.pack(">I2s2", 51, string.pack(">s2", string.pack(">I2s2", 29, x25519_basepoint)))
  elseif version_name == "DTLSv1.2" then
    local sigs = pack_u16_list({2052, 2053, 1027, 1283, 1025, 1281})
    extensions[#extensions + 1] = string.pack(">I2s2", 13, string.pack(">s2", sigs))
  end
  return table.concat(extensions)
end

local function ciphers_for_version(version_name)
  if version_name == "DTLSv1.3" then
    local ciphers = {}
    for _, cipher in ipairs(TLS13_CIPHERS) do ciphers[#ciphers + 1] = cipher end
    for _, cipher in ipairs(TLS12_CIPHERS) do ciphers[#ciphers + 1] = cipher end
    return ciphers
  elseif version_name == "DTLSv1.2" then
    return TLS12_CIPHERS
  end
  return LEGACY_CIPHERS
end

local function build_client_hello(version_name, cookie, sequence)
  local version = version_name == "DTLSv1.3" and DTLS_VERSIONS["DTLSv1.2"] or DTLS_VERSIONS[version_name]
  local ciphers = pack_u16_list(ciphers_for_version(version_name))
  local body = string.pack(">I2", version)
      .. rand.random_string(32)
      .. string.char(0)
      .. string.pack(">s1", cookie or "")
      .. string.pack(">s2", ciphers)
      .. string.pack(">s1", "\0")
      .. string.pack(">s2", build_extensions(version_name))
  local handshake = string.char(TLS_CLIENT_HELLO)
      .. i24(#body)
      .. string.pack(">I2", sequence)
      .. i24(0)
      .. i24(#body)
      .. body
  return string.char(TLS_HANDSHAKE)
      .. string.pack(">I2I2I2I2I2I2", version, 0, 0, 0, sequence, #handshake)
      .. handshake
end

local function parse_extensions(body, i)
  local ext_types, selected_version = {}, ""
  if i <= #body then
    local ext_blob
    ext_blob, i = read_vec(body, i, 2)
    if ext_blob then
      local eo = 1
      while eo + 3 <= #ext_blob do
        local et = u16(ext_blob, eo)
        local el = u16(ext_blob, eo + 2)
        if not et or not el or eo + 3 + el > #ext_blob then break end
        local ed = ext_blob:sub(eo + 4, eo + 3 + el)
        eo = eo + 4 + el
        ext_types[#ext_types + 1] = et
        if et == 43 and #ed == 2 then selected_version = tostring(u16(ed, 1)) end
      end
    end
  end
  return ext_types, selected_version
end

local function dtls_server_features(body)
  if #body < 38 then return nil end
  local version = u16(body, 1)
  local i = 35
  local _, next_i = read_vec(body, i, 1)
  if not next_i or next_i + 2 > #body then return nil end
  i = next_i
  local cipher = u16(body, i)
  if not cipher then return nil end
  i = i + 3
  local ext_types, selected_version = parse_extensions(body, i)
  return ("dtls|server|v=%d|c=%d|e=%s|sv=%s"):format(
    version, cipher, join_ints(ext_types), selected_version)
end

local function parse_dtls_response(data)
  local offset = 1
  while offset + 12 <= #data do
    local content_type = data:byte(offset)
    local version = u16(data, offset + 1)
    local length = u16(data, offset + 11)
    if not version or not length or (version & 0xff00) ~= 0xfe00 then return nil end
    local record = data:sub(offset + 13, offset + 12 + length)
    offset = offset + 13 + length
    if content_type == TLS_HANDSHAKE then
      local h = 1
      while h + 11 <= #record do
        local hs_type = record:byte(h)
        local hs_len = u24(record, h + 1)
        local fragment_offset = u24(record, h + 6)
        local fragment_len = u24(record, h + 9)
        if not hs_len or not fragment_offset or not fragment_len or h + 11 + fragment_len > #record then break end
        local body = record:sub(h + 12, h + 11 + fragment_len)
        h = h + 12 + fragment_len
        if fragment_offset == 0 and fragment_len == hs_len then
          if hs_type == DTLS_HELLO_VERIFY_REQUEST then
            local cookie = read_vec(body, 3, 1)
            if cookie then return nil, cookie end
          elseif hs_type == TLS_SERVER_HELLO then
            return dtls_server_features(body)
          end
        end
      end
    end
  end
  return nil
end

local function get_dtls_features(host, port, version_name)
  local sock = nmap.new_socket("udp")
  sock:set_timeout(timeout())
  if not sock:connect(host, port) then return nil end

  local flow = socket_flow(sock, host, port)
  local status = sock:send(build_client_hello(version_name, "", 0))
  if not status then sock:close(); return nil end
  local ok, data = sock:receive()
  if not ok or not data then sock:close(); return nil end

  local features, cookie = parse_dtls_response(data)
  if features then sock:close(); return features, flow end
  if cookie and #cookie > 0 then
    status = sock:send(build_client_hello(version_name, cookie, 1))
    if not status then sock:close(); return nil end
    ok, data = sock:receive()
    if ok and data then
      features = parse_dtls_response(data)
    end
  end
  sock:close()
  if features then return features, flow end
  return nil
end

local function result(features, flow)
  local mode = "active"
  local fingerprint, digest = fan1("dtls", "server", mode, features)
  return {
    mode = mode,
    protocol = "dtls",
    role = "server",
    fingerprint = fingerprint,
    features = features,
    sha256 = digest,
    flow = flow,
  }
end

action = function(host, port)
  for _, version_name in ipairs(dtls_versions()) do
    local features, fp_flow = get_dtls_features(host, port, version_name)
    if features then
      nmap.set_port_state(host, port, "open")
      return result(features, fp_flow)
    end
  end
  return nil
end
