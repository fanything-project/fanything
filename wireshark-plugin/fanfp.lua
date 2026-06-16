-- fanfp.lua — FAN/1 fingerprinting post-dissector for Wireshark
--
-- Adds fan1:tls and fan1:ssh fingerprints to the packet tree and exposes
-- them as display-filter fields:
--   fanfp.fingerprint   fanfp.features   fanfp.sha256
--   fanfp.protocol      fanfp.role
--
-- Requirements: Wireshark ≥ 3.4 (Lua 5.1 with 'bit' library, or Lua 5.3+)
--
-- Install (choose one):
--   • Copy to your Wireshark personal plugins folder:
--       Linux/macOS: ~/.local/lib/wireshark/plugins/   (or ~/.wireshark/plugins/)
--       Windows:     %APPDATA%\Wireshark\plugins\
--   • Load on demand:
--       wireshark  -X lua_script:fanfp.lua  capture.pcap
--       tshark     -X lua_script:fanfp.lua  -r capture.pcap -T fields \
--                  -e fanfp.fingerprint -e fanfp.features
--
-- Field names used from built-in dissectors (verify with your Wireshark version):
--   tshark -G fields | grep -E '^tls\.handshake|^ssh\.'

-- ─── Bit-operation compatibility (Lua 5.1 + bit library, or Lua 5.3+) ─────────

local _band, _bxor, _bor, _bnot, _rsh, _lsh, _rrot

if type(bit) == "table" then
    -- Lua 5.1 / LuaJIT: use the 'bit' library bundled with older Wireshark builds
    _band = bit.band
    _bxor = bit.bxor
    _bor  = bit.bor
    _bnot = bit.bnot
    _rsh  = bit.rshift
    _lsh  = bit.lshift
    _rrot = bit.ror
elseif _VERSION >= "Lua 5.3" then
    local M = 0xFFFFFFFF
    _band = function(a, b) return  a & b         end
    _bxor = function(a, b) return  a ~ b         end
    _bor  = function(a, b) return  a | b         end
    _bnot = function(a)    return (~a) & M        end
    _rsh  = function(a, n) return (a & M) >> n   end
    _lsh  = function(a, n) return (a << n) & M   end
    _rrot = function(a, n) return _bor(_rsh(a, n), _lsh(a, 32 - n)) end
else
    error("fanfp.lua: requires Lua 5.3+ or the 'bit' library (Lua 5.1/LuaJIT)")
end

-- ─── SHA-256 (pure Lua, portable) ────────────────────────────────────────────

local _sha256
do
    local K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    }

    local H0 = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    }

    -- Read 4 bytes big-endian from string at position i (1-indexed)
    local function u32be(s, i)
        local a, b, c, d = string.byte(s, i, i + 3)
        return ((a or 0) * 16777216) + ((b or 0) * 65536) + ((c or 0) * 256) + (d or 0)
    end

    -- Unsigned 32-bit hex string, portable across LuaJIT and Lua 5.x.
    -- string.format("%08x") sign-extends values ≥ 2³¹ to 64-bit in LuaJIT,
    -- producing 16-char output. We convert digit-by-digit instead.
    local _HEX = "0123456789abcdef"
    local function u32hex(n)
        if type(bit) == "table" then
            -- LuaJIT: bit.tohex handles signed 32-bit integers correctly
            return bit.tohex(n)
        end
        n = math.floor(n) % 4294967296
        local r = {}
        for i = 8, 1, -1 do
            r[i] = _HEX:sub(n % 16 + 1, n % 16 + 1)
            n = math.floor(n / 16)
        end
        return table.concat(r)
    end

    local function u32add(...)
        local s = 0
        for _, v in ipairs({...}) do s = (s + v) % 4294967296 end
        return s
    end

    local function compress(h, block)
        local w = {}
        for i = 1, 16 do
            w[i] = u32be(block, (i - 1) * 4 + 1)
        end
        for i = 17, 64 do
            local s0 = _bxor(_rrot(w[i-15], 7), _bxor(_rrot(w[i-15], 18), _rsh(w[i-15], 3)))
            local s1 = _bxor(_rrot(w[i-2], 17), _bxor(_rrot(w[i-2], 19), _rsh(w[i-2], 10)))
            w[i] = u32add(w[i-16], s0, w[i-7], s1)
        end

        local a, b, c, d, e, f, g, hh =
            h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8]

        for i = 1, 64 do
            local S1  = _bxor(_rrot(e, 6), _bxor(_rrot(e, 11), _rrot(e, 25)))
            local ch  = _bxor(_band(e, f), _band(_bnot(e), g))
            local t1  = u32add(hh, S1, ch, K[i], w[i])
            local S0  = _bxor(_rrot(a, 2), _bxor(_rrot(a, 13), _rrot(a, 22)))
            local maj = _bxor(_band(a, b), _bxor(_band(a, c), _band(b, c)))
            local t2  = u32add(S0, maj)

            hh = g; g = f; f = e; e = u32add(d, t1)
            d  = c; c = b; b = a; a = u32add(t1, t2)
        end

        return {
            u32add(h[1], a), u32add(h[2], b), u32add(h[3], c), u32add(h[4], d),
            u32add(h[5], e), u32add(h[6], f), u32add(h[7], g), u32add(h[8], hh),
        }
    end

    -- Pad message and return SHA-256 hex digest (matches Python hashlib.sha256)
    _sha256 = function(msg)
        local len = #msg
        -- Padding: 0x80, then zeros, then 8-byte big-endian bit-length
        local z = (55 - len % 64) % 64
        local bitlen_hi = math.floor(len * 8 / 4294967296)
        local bitlen_lo = (len * 8) % 4294967296
        local pad = "\x80" .. string.rep("\x00", z)
                 .. string.char(
                        math.floor(bitlen_hi / 16777216) % 256,
                        math.floor(bitlen_hi /    65536) % 256,
                        math.floor(bitlen_hi /      256) % 256,
                        bitlen_hi % 256,
                        math.floor(bitlen_lo / 16777216) % 256,
                        math.floor(bitlen_lo /    65536) % 256,
                        math.floor(bitlen_lo /      256) % 256,
                        bitlen_lo % 256)
        local data = msg .. pad
        local h = { H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7], H0[8] }
        for i = 1, #data, 64 do
            h = compress(h, data:sub(i, i + 63))
        end
        return u32hex(h[1]) .. u32hex(h[2]) .. u32hex(h[3]) .. u32hex(h[4])
            .. u32hex(h[5]) .. u32hex(h[6]) .. u32hex(h[7]) .. u32hex(h[8])
    end
end

-- ─── Base64url (no padding) ───────────────────────────────────────────────────

local function base64url(s)
    local alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    local out = {}
    local n = #s
    for i = 1, n, 3 do
        local b0 = string.byte(s, i)     or 0
        local b1 = string.byte(s, i + 1) or 0
        local b2 = string.byte(s, i + 2) or 0
        local v = b0 * 65536 + b1 * 256 + b2
        out[#out+1] = alpha:sub(math.floor(v / 262144) % 64 + 1, math.floor(v / 262144) % 64 + 1)
        out[#out+1] = alpha:sub(math.floor(v /   4096) % 64 + 1, math.floor(v /   4096) % 64 + 1)
        if i + 1 <= n then
            out[#out+1] = alpha:sub(math.floor(v /     64) % 64 + 1, math.floor(v /     64) % 64 + 1)
        end
        if i + 2 <= n then
            out[#out+1] = alpha:sub(                 v  % 64 + 1,                  v  % 64 + 1)
        end
    end
    return table.concat(out)
end

-- ─── FAN/1 core ──────────────────────────────────────────────────────────────

local function fan1(protocol, role, features)
    local digest  = _sha256(features)
    local encoded = base64url(features)
    return string.format("fan1:%s:%s:%s:sha256:%s", protocol, role, encoded, digest), digest
end

-- ─── GREASE / helpers ────────────────────────────────────────────────────────

local function is_grease(v)
    return _band(v, 0x0F0F) == 0x0A0A
       and _band(v, 0x00FF) == _band(_rsh(v, 8), 0x00FF)
end

local function collect_ints(field_fn)
    local result = {}
    for _, fi in ipairs({ field_fn() }) do
        if fi and fi.value then
            result[#result+1] = fi.value
        end
    end
    return result
end

local function collect_strs(field_fn)
    local result = {}
    for _, fi in ipairs({ field_fn() }) do
        if fi and fi.value then
            result[#result+1] = tostring(fi.value)
        end
    end
    return result
end

local function join_ints(values, grease_filter)
    local parts = {}
    for _, v in ipairs(values) do
        if not (grease_filter and is_grease(v)) then
            parts[#parts+1] = tostring(v)
        end
    end
    return table.concat(parts, "-")
end

-- ─── Protocol definition ─────────────────────────────────────────────────────

local p_fanfp = Proto("fanfp", "FAN/1 Fingerprint")

local pf = {
    fingerprint = ProtoField.string("fanfp.fingerprint", "FAN/1 Fingerprint"),
    features    = ProtoField.string("fanfp.features",    "FAN/1 Features"),
    sha256      = ProtoField.string("fanfp.sha256",      "SHA-256"),
    protocol    = ProtoField.string("fanfp.protocol",    "Protocol"),
    role        = ProtoField.string("fanfp.role",        "Role"),
}
p_fanfp.fields = { pf.fingerprint, pf.features, pf.sha256, pf.protocol, pf.role }

-- ─── Field extractors (must be at top level, not inside the dissector) ────────
--
-- TLS fields — confirmed against Wireshark 3.6+ / 4.x.
-- If a field is missing for your build, check:  tshark -G fields | grep tls.handshake

local f_tls_hs_type  = Field.new("tls.handshake.type")
local f_tls_version  = Field.new("tls.handshake.version")
local f_tls_cipher   = Field.new("tls.handshake.ciphersuite")
local f_tls_ext_type = Field.new("tls.handshake.extension.type")
local f_tls_groups   = Field.new("tls.handshake.extensions_supported_group")
local f_tls_points   = Field.new("tls.handshake.extensions_ec_point_format")
local f_tls_sv       = Field.new("tls.handshake.extensions.supported_version")
local f_tls_alpn     = Field.new("tls.handshake.extensions_alpn_str")
local f_tls_sig      = Field.new("tls.handshake.sig_hash_alg")

-- SSH fields — confirmed against Wireshark 4.x.
-- Check with:  tshark -G fields | grep '^ssh\.'
local f_ssh_protocol  = Field.new("ssh.protocol")
local f_ssh_kex       = Field.new("ssh.kex_algorithms")
local f_ssh_hostkey   = Field.new("ssh.server_host_key_algorithms")
local f_ssh_enc_c2s   = Field.new("ssh.encryption_algorithms_client_to_server")
local f_ssh_enc_s2c   = Field.new("ssh.encryption_algorithms_server_to_client")
local f_ssh_mac_c2s   = Field.new("ssh.mac_algorithms_client_to_server")
local f_ssh_mac_s2c   = Field.new("ssh.mac_algorithms_server_to_client")
local f_ssh_comp_c2s  = Field.new("ssh.compression_algorithms_client_to_server")
local f_ssh_comp_s2c  = Field.new("ssh.compression_algorithms_server_to_client")
local f_ssh_lang_c2s  = Field.new("ssh.languages_client_to_server")
local f_ssh_lang_s2c  = Field.new("ssh.languages_server_to_client")
local f_ssh_follows   = Field.new("ssh.first_kex_packet_follows")
-- tcp.stream is used to correlate the banner (earlier frame) with the KEXINIT
local f_tcp_stream    = Field.new("tcp.stream")

-- QUIC fields — confirmed against Wireshark 3.6+ / 4.x.
-- Check with:  tshark -G fields | grep '^quic\.'
local f_quic_version   = Field.new("quic.version")
local f_quic_token_len = Field.new("quic.token_length")  -- present only in Initial packets
local f_quic_dcil      = Field.new("quic.dcil")
local f_quic_scil      = Field.new("quic.scil")
local f_quic_length    = Field.new("quic.length")

-- Per-stream banner cache: stream_index → {client=..., server=...}
-- The SSH banner arrives in its own TCP segment before KEXINIT; we cache it
-- here so we can include id= in the KEXINIT fingerprint.
local ssh_banner_cache = {}

-- ─── TLS fingerprinting ───────────────────────────────────────────────────────

-- Returns a list of {role, features} pairs for every TLS handshake in the frame.
local function tls_fingerprints()
    local results = {}

    -- QUIC frames carry TLS inside CRYPTO frames; skip here so quic_fingerprints()
    -- handles them exclusively and avoids duplicate entries.
    if #{ f_quic_version() } > 0 then return results end

    -- Collect all handshake types present in this frame
    local hs_types = collect_ints(f_tls_hs_type)
    if #hs_types == 0 then return results end

    -- Shared field sets (may interleave if multiple records, but each frame
    -- typically carries one direction; we iterate over detected types)
    local versions  = collect_ints(f_tls_version)
    local ciphers   = collect_ints(f_tls_cipher)
    local ext_types = collect_ints(f_tls_ext_type)
    local groups    = collect_ints(f_tls_groups)
    local points    = collect_ints(f_tls_points)
    local sv_list   = collect_ints(f_tls_sv)
    local alpn_list = collect_strs(f_tls_alpn)
    local sigs      = collect_ints(f_tls_sig)

    local version = versions[1] or 0

    for _, hs_type in ipairs(hs_types) do
        if hs_type == 1 then
            -- ClientHello
            -- tls|client|v=<v>|c=<ciphers>|e=<exts>|g=<groups>|p=<points>|sv=<sv>|alpn=<alpn>|sig=<sig>
            local features = string.format(
                "tls|client|v=%d|c=%s|e=%s|g=%s|p=%s|sv=%s|alpn=%s|sig=%s",
                version,
                join_ints(ciphers,   true),
                join_ints(ext_types, true),
                join_ints(groups,    false),
                join_ints(points,    false),
                join_ints(sv_list,   true),
                table.concat(alpn_list, ","),
                join_ints(sigs,      false))
            results[#results+1] = { role = "client", features = features }

        elseif hs_type == 2 then
            -- ServerHello — selected cipher is ciphers[1], sv is sv_list[1]
            -- tls|server|v=<v>|c=<cipher>|e=<exts>|sv=<sv>
            local features = string.format(
                "tls|server|v=%d|c=%s|e=%s|sv=%s",
                version,
                tostring(ciphers[1] or ""),
                join_ints(ext_types, true),
                tostring(sv_list[1] or ""))
            results[#results+1] = { role = "server", features = features }
        end
    end

    return results
end

-- ─── SSH fingerprinting ───────────────────────────────────────────────────────

-- Returns a {role, features} pair if an SSH KEXINIT is present in the frame,
-- or nil if there is no SSH fingerprint-able content.
-- The SSH protocol banner (ssh.protocol) arrives in its own TCP segment before
-- the KEXINIT, so we cache it per tcp.stream and look it up here.
local function ssh_fingerprint()
    local stream_fi = { f_tcp_stream() }
    local stream_key = (stream_fi[1] and tostring(stream_fi[1].value)) or "?"

    -- ── Banner-only frame: cache the software id and return ──────────────────
    local proto_fi = { f_ssh_protocol() }
    if #proto_fi > 0 then
        if not ssh_banner_cache[stream_key] then
            ssh_banner_cache[stream_key] = {}
        end
        local raw = tostring(proto_fi[1].value):gsub("%s+$", "")
        -- "SSH-2.0-OpenSSH_8.9p1" → "OpenSSH_8.9p1"
        local sid = raw:match("^SSH%-%S-%-(.+)$") or raw
        -- The first banner seen on a stream is the client, second is the server.
        if not ssh_banner_cache[stream_key].client then
            ssh_banner_cache[stream_key].client = sid
        else
            ssh_banner_cache[stream_key].server = sid
        end
    end

    -- ── KEXINIT frame: build fingerprint ─────────────────────────────────────
    local kex_fi = { f_ssh_kex() }
    if #kex_fi == 0 then return nil end

    -- Look up the cached banner for this stream direction.
    -- A KEXINIT with kex_algorithms belongs to the peer that owns those algos.
    -- We don't know the direction from the field alone, so we pop from the cache
    -- in order: first KEXINIT seen gets the client banner, second gets server.
    local cache = ssh_banner_cache[stream_key] or {}
    local software_id
    if not cache._kexinit1_done then
        software_id = cache.client or ""
        cache._kexinit1_done = true
    else
        software_id = cache.server or ""
    end
    if not ssh_banner_cache[stream_key] then
        ssh_banner_cache[stream_key] = cache
    end

    local function first_str(fi_list)
        return (#fi_list > 0 and tostring(fi_list[1].value)) or ""
    end

    local kex      = first_str({ f_ssh_kex() })
    local hostkey  = first_str({ f_ssh_hostkey() })
    local enc_c2s  = first_str({ f_ssh_enc_c2s() })
    local enc_s2c  = first_str({ f_ssh_enc_s2c() })
    local mac_c2s  = first_str({ f_ssh_mac_c2s() })
    local mac_s2c  = first_str({ f_ssh_mac_s2c() })
    local comp_c2s = first_str({ f_ssh_comp_c2s() })
    local comp_s2c = first_str({ f_ssh_comp_s2c() })
    local lang_c2s = first_str({ f_ssh_lang_c2s() })
    local lang_s2c = first_str({ f_ssh_lang_s2c() })

    local follows = ""
    local fol_fi = { f_ssh_follows() }
    if #fol_fi > 0 then
        local v = fol_fi[1].value
        follows = (v and v ~= 0 and v ~= false) and "True" or "False"
    end

    local features = string.format(
        "ssh|peer|id=%s|kex=%s|hostkey=%s|enc_c2s=%s|enc_s2c=%s"
        .. "|mac_c2s=%s|mac_s2c=%s|comp_c2s=%s|comp_s2c=%s"
        .. "|lang_c2s=%s|lang_s2c=%s|follows=%s",
        software_id, kex, hostkey, enc_c2s, enc_s2c,
        mac_c2s, mac_s2c, comp_c2s, comp_s2c,
        lang_c2s, lang_s2c, follows)

    return { role = "peer", features = features }
end

-- ─── QUIC fingerprinting ─────────────────────────────────────────────────────

-- Returns a list of {role, features} pairs for QUIC Initial packets.
-- When Wireshark decrypts the QUIC Initial CRYPTO frame the TLS handshake
-- fields become visible in the same frame — we reuse the existing TLS field
-- extractors.  If the packet was not decrypted we fall back to the QUIC long
-- header metadata (connection IDs, token length, payload length).
--
-- Feature string formats (matching PR #5 / fanfp.py):
--   decrypted client: quic|client|v=<qver>|tls_v=<tlsver>|c=…|e=…|g=…|p=…|sv=…|alpn=…|sig=…
--   decrypted server: quic|server|v=<qver>|tls_v=<tlsver>|c=…|e=…|sv=…
--   fallback:         quic|peer|v=<qver>|type=initial|dcid_len=…|scid_len=…|token_len=…|len=…
local function quic_fingerprints()
    local results = {}

    -- Only fire on QUIC long-header (Initial) packets
    local quic_vers  = collect_ints(f_quic_version)
    if #quic_vers == 0 then return results end
    local token_lens = collect_ints(f_quic_token_len)
    if #token_lens == 0 then return results end   -- not an Initial packet

    local qver = quic_vers[1]

    -- Check whether the QUIC Initial was decrypted (TLS handshake fields visible)
    local hs_types = collect_ints(f_tls_hs_type)

    if #hs_types > 0 then
        local versions  = collect_ints(f_tls_version)
        local ciphers   = collect_ints(f_tls_cipher)
        local ext_types = collect_ints(f_tls_ext_type)
        local groups    = collect_ints(f_tls_groups)
        local points    = collect_ints(f_tls_points)
        local sv_list   = collect_ints(f_tls_sv)
        local alpn_list = collect_strs(f_tls_alpn)
        local sigs      = collect_ints(f_tls_sig)

        local tls_ver = versions[1] or 0

        for _, hs_type in ipairs(hs_types) do
            if hs_type == 1 then
                -- ClientHello inside QUIC Initial
                local features = string.format(
                    "quic|client|v=%d|tls_v=%d|c=%s|e=%s|g=%s|p=%s|sv=%s|alpn=%s|sig=%s",
                    qver, tls_ver,
                    join_ints(ciphers,   true),
                    join_ints(ext_types, true),
                    join_ints(groups,    false),
                    join_ints(points,    false),
                    join_ints(sv_list,   true),
                    table.concat(alpn_list, ","),
                    join_ints(sigs,      false))
                results[#results+1] = { role = "client", features = features }

            elseif hs_type == 2 then
                -- ServerHello inside QUIC Initial
                local features = string.format(
                    "quic|server|v=%d|tls_v=%d|c=%s|e=%s|sv=%s",
                    qver, tls_ver,
                    tostring(ciphers[1] or ""),
                    join_ints(ext_types, true),
                    tostring(sv_list[1] or ""))
                results[#results+1] = { role = "server", features = features }
            end
        end
    else
        -- Fallback: header-only fingerprint (no decryption)
        local dcil_fi = collect_ints(f_quic_dcil)
        local scil_fi = collect_ints(f_quic_scil)
        local len_fi  = collect_ints(f_quic_length)
        local features = string.format(
            "quic|peer|v=%d|type=initial|dcid_len=%d|scid_len=%d|token_len=%d|len=%d",
            qver,
            dcil_fi[1] or 0,
            scil_fi[1] or 0,
            token_lens[1] or 0,
            len_fi[1] or 0)
        results[#results+1] = { role = "peer", features = features }
    end

    return results
end

-- ─── Main dissector ───────────────────────────────────────────────────────────

function p_fanfp.dissector(tvb, pinfo, root)
    local candidates = {}

    -- TLS (TCP only; QUIC frames are handled below)
    local ok, tls_fps = pcall(tls_fingerprints)
    if ok then
        for _, fp in ipairs(tls_fps) do
            candidates[#candidates+1] = { protocol = "tls", role = fp.role, features = fp.features }
        end
    end

    -- QUIC
    local ok3, quic_fps = pcall(quic_fingerprints)
    if ok3 then
        for _, fp in ipairs(quic_fps) do
            candidates[#candidates+1] = { protocol = "quic", role = fp.role, features = fp.features }
        end
    end

    -- SSH
    local ok2, ssh_fp = pcall(ssh_fingerprint)
    if ok2 and ssh_fp then
        candidates[#candidates+1] = { protocol = "ssh", role = ssh_fp.role, features = ssh_fp.features }
    end

    if #candidates == 0 then return end

    local tree = root:add(p_fanfp, tvb(), "FAN/1 Fingerprints")

    for _, c in ipairs(candidates) do
        local fingerprint, digest = fan1(c.protocol, c.role, c.features)

        local sub = tree:add(p_fanfp, tvb(),
            string.format("[%s/%s] %s", c.protocol, c.role,
                          fingerprint:sub(1, 40) .. "…"))

        sub:add(pf.protocol,    tvb(), c.protocol)
        sub:add(pf.role,        tvb(), c.role)
        sub:add(pf.features,    tvb(), c.features)
        sub:add(pf.fingerprint, tvb(), fingerprint)
        sub:add(pf.sha256,      tvb(), digest)
    end
end

register_postdissector(p_fanfp)
