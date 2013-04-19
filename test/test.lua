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
]]

function addrs(ip_addr)
    return ""..ip_addr.byte1.."."..ip_addr.byte2.."."..ip_addr.byte3.."."..ip_addr.byte4
end

local devs = pcap.findalldevs()
print("Devices found: "..#devs)
for k,v in ipairs(devs) do
    print(""..k..". "..v.name.." : "..v.description)
end

local pc = pcap.open_live(devs[4].name)
pc:set_filter("ip and udp")
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
    print("ADDR: "..addrs(hdr.saddr).." -> "..addrs(hdr.daddr))
    local ip_len =  bit.band(hdr.ver_ihl, 0xf) * 4
    print("IP len: "..ip_len)
    local udphdr = ffi.cast("udp_header *", data + 14 + ip_len)
    print("sport: "..udphdr.sport..", dport:"..udphdr.dport)
end