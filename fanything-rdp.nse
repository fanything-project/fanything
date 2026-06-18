local base64 = require "base64"
local nmap = require "nmap"
local openssl = require "openssl"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts FAN/1 fingerprints from live RDP X.224 services.

The script sends a TPKT/X.224 Connection Request with an RDP Negotiation
Request and fingerprints the responder X.224 Connection Confirm plus same-packet
RDP Negotiation Response when present.
]]

---
-- @usage
-- nmap -Pn -p3389 --script ./fanything-rdp.nse <target>
--
-- @output
-- PORT     STATE SERVICE
-- 3389/tcp open  ms-wbt-server
-- | fanything-rdp:
-- |   mode: active
-- |   protocol: rdp
-- |   role: server
-- |   fingerprint: fan1:rdp:server:active:...
-- |   features: rdp|server|tpkt_v=3|tpkt_rsv=0|tpkt_len=19|x224_len=14|pdu=208|dst_ref=0|src_ref=4660|class=0|neg_type=2|neg_flags=1|neg_len=8|neg_proto=|neg_selected=2
-- |   sha256: ...
-- |   flow:
-- |     src: 192.0.2.10
-- |     sport: 3389
-- |     dst: 198.51.100.5
-- |_    dport: 53539
--
-- @args fanything-rdp.timeout Socket timeout in milliseconds. Default: 5000.
-- @args fanything-rdp.requested-protocols Decimal RDP Negotiation Request
-- protocols bitmask. Default: 11 (SSL, HYBRID, HYBRID_EX).
-- @args fanything-rdp.force Run on any open TCP port. Useful for tests.

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
  return shortport.port_or_service(3389, {"ms-wbt-server", "rdp"}, "tcp", "open")(host, port)
end

local function timeout()
  return tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 5000
end

local function requested_protocols()
  local value = tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".requested-protocols")) or 11
  if value < 0 then value = 0 end
  if value > 0xffffffff then value = 0xffffffff end
  return value
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

local function u16be(s, i)
  local a, b = s:byte(i, i + 1)
  if not a or not b then return nil end
  return a * 256 + b
end

local function u16le(s, i)
  local a, b = s:byte(i, i + 1)
  if not a or not b then return nil end
  return a + b * 256
end

local function u32le(s, i)
  local a, b, c, d = s:byte(i, i + 3)
  if not a or not b or not c or not d then return nil end
  return ((d * 256 + c) * 256 + b) * 256 + a
end

local function build_probe()
  local neg = string.char(1, 0) .. string.pack("<I2I4", 8, requested_protocols())
  local x224 = string.char(6 + #neg, 0xe0) .. string.pack(">I2I2B", 0, 0, 0) .. neg
  return string.char(3, 0) .. string.pack(">I2", #x224 + 4) .. x224
end

local function parse_rdp_x224(data)
  if not data or #data < 11 then return nil end
  if data:byte(1) ~= 3 or data:byte(2) ~= 0 then return nil end
  local tpkt_version = data:byte(1)
  local tpkt_reserved = data:byte(2)
  local tpkt_len = u16be(data, 3)
  if not tpkt_len or tpkt_len < 7 or tpkt_len > #data then return nil end
  local tpkt = data:sub(1, tpkt_len)
  local x224_len = tpkt:byte(5)
  local pdu = tpkt:byte(6)
  if pdu ~= 0xd0 and pdu ~= 0xe0 then return nil end

  local role = pdu == 0xd0 and "server" or "client"
  local dst_ref = u16be(tpkt, 7)
  local src_ref = u16be(tpkt, 9)
  local class_opt = tpkt:byte(11)
  if not dst_ref or not src_ref or not class_opt then return nil end

  local neg_type, neg_flags, neg_len, neg_proto, neg_selected = "", "", "", "", ""
  for i = 12, #tpkt - 7 do
    local ntype = tpkt:byte(i)
    if ntype == 1 or ntype == 2 then
      local nlen = u16le(tpkt, i + 2)
      if nlen and nlen >= 8 and i + nlen - 1 <= #tpkt then
        local nvalue = u32le(tpkt, i + 4)
        neg_type = tostring(ntype)
        neg_flags = tostring(tpkt:byte(i + 1))
        neg_len = tostring(nlen)
        if ntype == 1 then
          neg_proto = tostring(nvalue)
        else
          neg_selected = tostring(nvalue)
        end
        break
      end
    end
  end

  local features = ("rdp|%s|tpkt_v=%d|tpkt_rsv=%d|tpkt_len=%d|x224_len=%d"
      .. "|pdu=%d|dst_ref=%d|src_ref=%d|class=%d|neg_type=%s|neg_flags=%s"
      .. "|neg_len=%s|neg_proto=%s|neg_selected=%s"):format(
      role, tpkt_version, tpkt_reserved, tpkt_len, x224_len, pdu, dst_ref,
      src_ref, class_opt, neg_type, neg_flags, neg_len, neg_proto, neg_selected)
  return role, features
end

local function get_rdp_features(host, port)
  local sock = nmap.new_socket()
  sock:set_timeout(timeout())
  if not sock:connect(host, port) then return nil end
  local flow = socket_flow(sock, host, port)

  local status = sock:send(build_probe())
  if not status then sock:close(); return nil end

  local ok, data = sock:receive_buf(function(buf)
    if #buf < 4 then return nil end
    local len = u16be(buf, 3)
    if not len or len < 4 then return nil end
    if #buf < len then return nil end
    return len, len
  end, true)
  sock:close()
  if not ok then return nil end

  local role, features = parse_rdp_x224(data)
  if role ~= "server" then return nil end
  return features, flow
end

local function result(features, flow)
  local mode = "active"
  local fingerprint, digest = fan1("rdp", "server", mode, features)
  return {
    mode = mode,
    protocol = "rdp",
    role = "server",
    fingerprint = fingerprint,
    features = features,
    sha256 = digest,
    flow = flow,
  }
end

action = function(host, port)
  local features, fp_flow = get_rdp_features(host, port)
  if not features then return nil end
  return result(features, fp_flow)
end
