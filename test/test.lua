local pcap = require("pcap")
local ffi = require("ffi")

local devs = pcap.findalldevs()
print("Devices found: "..#devs)
for k,v in ipairs(devs) do
    print(""..k..". "..v.name.." : "..v.description)
end

local pc = pcap.open_live(devs[4].name)
pc:loop(1000, function(data, ts, len)
    print("ts: "..ts..", len: "..len)
    if len > 600 then 
        return 1
    end
end)