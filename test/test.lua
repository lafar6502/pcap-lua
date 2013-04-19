local pcap = require("pcap")
local ffi = require("ffi")
local bit = require("bit")

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


printx(ntohs(0x1234))

local devs = pcap.findalldevs()
print("Devices found: "..#devs)
for k,v in ipairs(devs) do
    print(""..k..". "..v.name.." : "..v.description)
end

local pc = pcap.open_live(devs[4].name)
pc:set_filter("ip and (udp or tcp)")
--[[
pc:loop(1000, function(data, ts, len)
    print("ts: "..ts..", len: "..len)
    local hdr = ffi.cast("ip_header", data + 14)
end)
--]]

for pkt, ts, len in pc.next, pc do
    print("ts: "..ts..", len: "..len)
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
        local content = ffi.string(payload, size_payload)
        print(content)
    elseif hdr.proto == 17 then
        local udphdr = ffi.cast("udp_header2 *", data + 14 + ip_len)
        bswap_bytes(udphdr.sport)
        bswap_bytes(udphdr.dport)
        udphdr = ffi.cast("udp_header*", udphdr)
        print(addrs(hdr.saddr)..":"..udphdr.sport.." -> "..addrs(hdr.daddr)..":"..udphdr.dport.." UDP ")
        
    else
    end
end