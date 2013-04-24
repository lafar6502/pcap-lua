local pcap = require("pcap")
local ffi = require("ffi")
local bit = require("bit")
local lio = require("io")

ffi.cdef[[
/* 4 bytes IP address */
typedef struct ip_address{
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
    uint8_t byte4;
} ip_address;

/* IPv4 header */
typedef struct ip_header{
    uint8_t  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    uint8_t  tos;            // Type of service 
    uint16_t tlen;           // Total length 
    uint16_t identification; // Identification
    uint16_t flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t  ttl;            // Time to live
    uint8_t  proto;          // Protocol
    uint16_t crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    uint32_t   op_pad;         // Option + Padding
} ip_header;

/* UDP header*/
typedef struct udp_header{
    uint16_t sport;          // Source port
    uint16_t dport;          // Destination port
    uint16_t len;            // Datagram length
    uint16_t crc;            // Checksum
} udp_header;

typedef struct udp_header2{
    uint8_t sport[2];          // Source port
    uint8_t dport[2];          // Destination port
    uint8_t len[2];            // Datagram length
    uint8_t crc[2];            // Checksum
} udp_header2;

typedef struct tcp_header {
    uint16_t sport;   /* source port */
    uint16_t dport;   /* destination port */
    uint32_t seq;     /* sequence number */
    uint32_t ack;     /* acknowledgement number */
    uint8_t  offx2;    /* data offset, rsvd */
    uint8_t  flags;
    uint16_t win;     /* window */
    uint16_t sum;     /* checksum */
    uint16_t urp;     /* urgent pointer */
} tcp_header;

typedef struct rtp_header {
    uint8_t b1;
    uint8_t payload_type;
    uint16_t seq;
    uint32_t tstamp;
    uint32_t ssrc;
    /*uint32_t csrc;*/
} rtp_header;
]]
--[[#define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
]]
    
function printx(x)
  print("0x"..bit.tohex(x))
end
function addrs(ip_addr)
    return ""..ip_addr.byte1.."."..ip_addr.byte2.."."..ip_addr.byte3.."."..ip_addr.byte4
end
function bswap_bytes(p)
    local t = p[0]
    p[0] = p[1]
    p[1] = t
end
function TH_OFF(th)
    return bit.rshift(bit.band(th.offx2, 0xf0), 4)
end


local ntohl = ffi.abi("le") and bit.bswap or function(x) return x end
function swap16(n)
    return bit.band(bit.bor(bit.lshift(n, 8), bit.rshift(bit.band(n, 0xff00), 8)), 0xffff)
end
local ntohs = ffi.abi("le") and swap16 or function(x) return x end


local devs = pcap.findalldevs()
print("Devices found: "..#devs)
for k,v in ipairs(devs) do
    print(""..k..". "..v.name.." : "..v.description)
end

local pc = pcap.open_live(devs[4].name)
pc:set_filter("ip and udp")

function string.startsWith(s1, s2)
    return s1:sub(1, s2:len()) == s2
end

function string.lines(s)
    local oidx, idx, ret = -2, nil, {}
    repeat
        idx = string.find(s, '\r\n', oidx + 2, false)
        table.insert(ret, s:sub(oidx + 2, idx and idx-1 or s:len()))
        oidx = idx
    until not idx
    return ret
end
function string.trim(s)
    return s:find'^%s*$' and '' or s:match'^%s*(.*%S)'
end
    
function check_sip_command(content)
    local s = content
    if content:len() > 100 then
        s = content:sub(1, 100)
    end
    local si, ei = s:find(' ')
    if si == nil then
        return false
    end
    local cmd = s:sub(1, si - 1)
    local cmdarr = {"INVITE ", "OPTIONS ", "NOTIFY ", "BYE ", "SIP ", "REGISTER ", "ACK "}
    return true, cmd
end



function parse_header(line)
    local idx = line:find(':')
    if idx ~= nil and idx > 0 then 
        local name = line:sub(1, idx - 1)
        local val = line:sub(idx + 1, #line)
        return name, val:trim()
    end
    return nil
end

-- return IN address of the audio stream
function get_sdp_audio_info(lines)
    local ln = lines
    if type(lines) == 'string' then ln = lines:lines() end
    local dt = {}
    for i,v in ipairs(ln) do
        local s,e,p = v:find('m=audio (%d+)')
        if s == 1 then dt.port = p end
        s,e,p = v:find('c=IN IP4 (.+)')
        if s == 1 then dt.ip = p end
    end
    return dt
end

--parses sip request headers and returns the header table plus packet payload (everything after the headers)
function parse_sip_request(content)
    local cs = content:find('\r\n\r\n')
    local hdrpart = cs and content:sub(1, cs - 1) or content
    local hdrdata = hdrpart:lines()
    local i1 = hdrdata[1]:find(' ')
    local hdr = {sipcommand = hdrdata[1]:sub(1,i1 - 1), sipcommand_args = hdrdata[1]:sub(i1 + 1, #hdrdata[1]), command=hdrdata[1]}
    for i=2,#hdrdata do
        local h,v = parse_header(hdrdata[i])
        if h then hdr[h]=v end
    end
    local dpart = ""
    if cs ~= nil then
        local ce = #content
        if hdr['Content-Length'] ~= nil then ce = cs + hdr['Content-Length'] end
        if ce > #content then ce = #content end
        dpart = content:sub(cs + 4, ce)
    end
    return hdr, dpart
end


function get_sip_invite_data(content)
    local hdr, data = parse_sip_request(content)
    print('data: '..data)
    hdr.sdpdata = get_sdp_audio_info(data)
    return hdr
end

function get_sip_data(content)
    local hdr,data = parse_sip_request(content)
    if hdr['Content-Type'] == 'application/sdp' then
        hdr.sdpdata = get_sdp_audio_info(data)
    else
        hdr.data = data
    end
    return hdr
end

g_sessions = {}
g_rtp = {}

-- after INVITE - register a new SIP session
function register_sip_session(callId, seq, tstamp, rtp_addr, rtp_port, sipdata)
    local session = {CallID = callId, CSeq = seq, StartTS = tstamp, status='INVITED', rtp_caller = rtp_addr..':'..rtp_port}
    g_sessions[callId] = session
    g_rtp[session.rtp_caller] = callId
end

-- SIP/20 200 OK after an invite, with SDP information
function register_sip_session_confirmation(callId, seq, rtp_addr, rtp_port)
    local ses = g_sessions[callId]
    if ses == nil then return end
    if ses.CSeq ~= seq then
        print('SEQ number not matching')
        return
    end
    if ses.status == 'INVITED' then
        ses.status = 'CONFIRMED'
        ses.rtp_callee = rtp_addr..':'..rtp_port
        g_rtp[ses.rtp_callee] = callId
        print('SESSION '..ses.CallID..' IS CONFIRMED')
    end
end
-- INVITE ACK (session begins)
function register_sip_session_ack(callId, seq)
    local ses = g_sessions[callId]
    if ses == nil then return end
    if ses.status == 'CONFIRMED' then
        ses.status = 'ACTIVE'
        print('SESSION '..ses.CallID..' IS ACTIVE expecting RTP '..ses.rtp_caller..' <-> '..ses.rtp_callee)
    end
end

-- SIP BYE
function register_sip_session_bye(callId, seq)
    local ses = g_sessions[callId]
    if ses == nil then return end
    ses.status = 'BYE'
    if ses.dest_file ~= nil then
        ses.dest_file:close()
        ses.dest_file = nil
    end
    if ses.orig_file ~= nil then
        ses.orig_file:close()
        ses.orig_file = nil
    end
    
    print('SESSION '..ses.CallID..' CLOSED')
end

-- periodic session table cleanup
function cleanup_sessions()
end


function process_sip_packet(tstamp, ip, isUdp, hdr, payload, payload_size, rawpacket)
    local content = ffi.string(payload, payload_size)
    local t, cmd = check_sip_command(content)
    if not t then return end
    local sip = get_sip_data(content)
    local callId,contentType,cseq,sdp = sip['Call-ID'], sip['Content-Type'], sip['CSeq'], sip.sdpdata
    
    if cmd == 'INVITE' then
        print('INVITE Call ID: '..sip['Call-ID']..' SEQ: '..sip.CSeq..'\nFrom'..sip.From..' To:'..sip.To..'  Media at:'..sip.sdpdata.ip..':'..sip.sdpdata.port)
        register_sip_session(sip['Call-ID'], sip.CSeq, tstamp, sip.sdpdata.ip, sip.sdpdata.port, sip)
    elseif cmd == 'BYE' then
        print('BYE '..sip['Call-ID']..' SEQ:'..sip.CSeq)
        register_sip_session_bye(sip['Call-ID'], sip.CSeq)
    elseif cmd == 'ACK' then
        print('ACK '..sip['Call-ID']..' SEQ:'..sip.CSeq)
        register_sip_session_ack(sip['Call-ID'], sip.CSeq)
    elseif cmd == 'SIP/2.0' then
        print('SIP/2.0 '..sip.sipcommand_args..', Call ID:'..sip['Call-ID']..' SEQ:'..sip.CSeq)
        if sip['Content-Type'] == 'application/sdp' then
            print('SDP!: '..sip.sdpdata.ip..':'..sip.sdpdata.port)
            register_sip_session_confirmation(sip['Call-ID'], sip.CSeq, sip.sdpdata.ip, sip.sdpdata.port)
        end
    end     
end

function check_rtp(payload, payload_size)
    if payload_size < ffi.sizeof('rtp_header') then return nil end
    local rthdr = ffi.cast('rtp_header*', payload)
    local ver = bit.band(rthdr.b1, 0xc0)
    if ver ~= 0x80 then return nil end
    local cc = bit.band(rthdr.b1, 0x0f)
    local x = bit.band(rthdr.b1, 0x10)
    local p = bit.band(rthdr.b1, 0x20)
    local ptype = bit.band(rthdr.payload_type, 0x80)
    print('RTP ver is '..ver..' and payload is '..ptype..' SEQ:'..ntohs(rthdr.seq)..',SSRC:'..ntohl(rthdr.ssrc)..' CC:'..cc..', X:'..x..',P:'..p)
    return ffi.sizeof('rtp_header') + cc * ffi.sizeof('uint32_t'), rthdr
end

g_fcnt = 0

function process_rtp_packet(tstamp, ip, isUdp, hdr, payload, payload_size, rawpacket)
    local hdsize, rthdr = check_rtp(payload, payload_size)
    if hdsize == nil then return nil end
    
    print('\r\nDoing RTP: '..addrs(ip.saddr)..":"..hdr.sport.." -> "..addrs(ip.daddr)..":"..hdr.dport)
    local cid = g_rtp[rthdr.ssrc]
    if cid == nil then
        local s1 = addrs(ip.saddr)..":"..hdr.sport
        local d = 'orig_ssrc'
        cid = g_rtp[s1]
        if cid == nil then
            s1 = addrs(ip.daddr)..':'..hdr.dport
            cid = g_rtp[s1]
            d = 'dest_ssrc'
        end
        if cid == nil then
            print("call not found for this RTP")
            return nil
        end
        g_rtp[rthdr.ssrc] = cid
        g_sessions[cid][d] = rthdr.ssrc
    end
    local ses = g_sessions[cid]
    ses.last_packet_ts = tstamp
    local fh = nil
    if ses.orig_ssrc == rthdr.ssrc then
        if ses.orig_file == nil then
            g_fcnt = g_fcnt + 1
            ses.orig_file = io.open("orig_"..g_fcnt..".wav", 'wb')
            print('opened orig file')
        end
        fh = ses.orig_file
    else
        if ses.dest_file == nil then
            g_fcnt = g_fcnt + 1
            ses.dest_file = io.open("dest_"..g_fcnt..".wav", 'wb')
            print('opened dest file')
        end
        fh = ses.dest_file
    end
    local rtpayload = ffi.cast('char*', payload + hdsize)
    local rtstr = ffi.string(ffi.cast('char*', payload + hdsize), payload_size - hdsize)
    print('writing '..#rtstr..' bytes to file')
    fh:write(rtstr)
    fh:flush()
end

function process_packet(tstamp, iphdr, isUdp, udphdr, payload, size_payload, rawpacket)
    local content = ffi.string(payload, size_payload)
    if isUdp then
        process_rtp_packet(tstamp, iphdr, isUdp, udphdr, payload, size_payload, rawpacket)
        
        if udphdr.sport == 5060 or udphdr.dport == 5060 then 
            print('\r\n'..addrs(iphdr.saddr)..":"..udphdr.sport.." -> "..addrs(iphdr.daddr)..":"..udphdr.dport.." UDP ")
            --print(content)
            local t, cmd = check_sip_command(content)
            if t then process_sip_packet(tstamp, iphdr, isUdp, udphdr, payload, size_payload, rawpacket) end
        end
    
    else
    end
end

for pkt, ts, len in pc.next, pc do
    --print("ts: "..ts..", len: "..len)
    local data = ffi.cast("char *", pkt)
    local hdr = ffi.cast("ip_header *", data + 14)
    
    local ip_len =  bit.band(hdr.ver_ihl, 0xf) * 4
    
    if hdr.proto == 6 then
        local tcphdr = ffi.cast("tcp_header*", data + 14 + ip_len)
        local size_tcp = TH_OFF(tcphdr)*4;
        print(addrs(hdr.saddr)..":"..tcphdr.sport.." -> "..addrs(hdr.daddr)..":"..tcphdr.dport.." TCP ")
        print('size tcp is '..size_tcp)
        local payload = data + 14 + ip_len + size_tcp;
        local size_payload = ntohs(hdr.tlen) - (14 + size_tcp);
        print('payload is '..payload[0]..' '..payload[1]..' '..payload[2])
        process_packet(ts, hdr, false, tcphdr, payload, size_payload, pkt)
    elseif hdr.proto == 17 then
        local udphdr = ffi.cast("udp_header2 *", data + 14 + ip_len)
        bswap_bytes(udphdr.sport)
        bswap_bytes(udphdr.dport)
        udphdr = ffi.cast("udp_header*", udphdr)
        local size_udp = ffi.sizeof("udp_header")
        local payload = data + 14 + ip_len + size_udp
        --print('PAY:'..payload[0]..'.'..payload[1]..'.'..payload[2]..'.'..payload[3])
        local size_payload = ntohs(hdr.tlen) - (14 + size_udp);
        process_packet(ts, hdr, true, udphdr, payload, size_payload, pkt)
        
    else
    end
end