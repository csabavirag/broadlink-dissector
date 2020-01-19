-- For luagcrypt:
-- Install Lua as described at https://github.com/nubix-io/stuart/wiki/Install-Lua-5.2-on-a-Mac
-- Install Luarocks : https://luarocks.org/releases/luarocks-3.2.1.tar.gz
--    ./configure && make && make install
-- Install libcrypt: brew install libgcrypt
-- Clone and install Luagcrypt: https://github.com/Lekensteyn/luagcrypt
--    move luagcrypt.so to /usr/local/lib/lua/5.2/ 

-- Related links:
-- https://blog.ipsumdomus.com/broadlink-smart-home-devices-complete-protocol-hack-bc0b4b397af1

local gcrypt = require("luagcrypt")

-- do not modify this table
local debug_level = {
    DISABLED = 0,
    LEVEL_1  = 1,
    LEVEL_2  = 2
}

-- set this DEBUG to debug_level.LEVEL_1 to enable printing debug_level info
-- set it to debug_level.LEVEL_2 to enable really verbose printing
-- note: this will be overridden by user's preference settings
local DEBUG = debug_level.LEVEL_1

local default_settings =
{
    debug_level  = DEBUG,
    port         = 80,
    aes_key      = "00000000000000000000000000000000",
    aes_defkey   = "097628343fe99e23765c1513accf8b02",
}

local dprint = function() end
local dprint2 = function() end
local function reset_debug_level()
    if default_settings.debug_level > debug_level.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua:", ...}," "))
        end

        if default_settings.debug_level > debug_level.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
-- call it now
reset_debug_level()

-- trivial protocol example
-- declare our protocol
broadlink = Proto("broadlink","Broadlink Protocol")


--------------------------------------------------------------------------------
-- preferences handling stuff
--------------------------------------------------------------------------------

-- a "enum" table for our enum pref, as required by Pref.enum()
-- having the "index" number makes ZERO sense, and is completely illogical
-- but it's what the code has expected it to be for a long time. Ugh.
local debug_pref_enum = {
    { 1,  "Disabled", debug_level.DISABLED },
    { 2,  "Level 1",  debug_level.LEVEL_1  },
    { 3,  "Level 2",  debug_level.LEVEL_2  },
}
broadlink.prefs.debug = Pref.enum("Debug", default_settings.debug_level,
                            "The debug printing level", debug_pref_enum)

broadlink.prefs.port  = Pref.uint("Port number", default_settings.port,
                            "The UDP port number for Broadlink protocol")

broadlink.prefs.aes_key = Pref.string("Decryption key", default_settings.aes_key, "128-bit AES key (in hex)")

----------------------------------------
-- a function for handling prefs being changed
function broadlink.prefs_changed()
    dprint2("prefs_changed called")

    default_settings.debug_level  = broadlink.prefs.debug
    reset_debug_level()

    default_settings.aes_key = broadlink.prefs.aes_key

    if default_settings.port ~= broadlink.prefs.port then
        -- remove old one, if not 0
        if default_settings.port ~= 0 then
            dprint2("removing Broadlink from port",default_settings.port)
            DissectorTable.get("udp.port"):remove(default_settings.port, broadlink)
        end
        -- set our new default
        default_settings.port = broadlink.prefs.port
        -- add new one, if not 0
        if default_settings.port ~= 0 then
            dprint2("adding Broadlink to port",default_settings.port)
            DissectorTable.get("udp.port"):add(default_settings.port, broadlink)
        end
    end

end

dprint2("Broadlink Prefs registered")

-- Convert a string of hexadecimal numbers to a bytes string
function fromhex(hex)
    if string.match(hex, "[^0-9a-fA-F]") then
        error("Invalid chars in hex")
    end
    if string.len(hex) % 2 == 1 then
        error("Hex string must be a multiple of two")
    end
    local s = string.gsub(hex, "..", function(v)
        return string.char(tonumber(v, 16))
    end)
    return s
end

local rcodes = {
        [0x06] = "Hello request",
        [0x07] = "Hello response",
        [0x1a] = "Discover request",
        [0x1b] = "Discover response",
        [0x14] = "Join request",
        [0x15] = "Join response",
        [0x65] = "Auth request",
        [0x3e9] = "Auth response",
        [0x6a] = "Command request",
        [0x3ee] = "Command response"
}
local rcmdstate = {[0x02] = "Set", [0x01] = "Get"}

-- the above rcodes table is used in this next ProtoField
local f_command         = ProtoField.uint16("broadlink.flags.command", "Command", base.HEX, rcodes)
local f_dev_type        = ProtoField.uint16("broadlink.flags.dev_type", "Device type", base.HEX)
local f_dev_mac         = ProtoField.ether("broadlink.flags.dev_mac", "MAC address")
local f_dev_name        = ProtoField.stringz("broadlink.flags.dev_name", "Device Name")
local f_dev_ip          = ProtoField.ipv4("broadlink.flags.dev_ip", "IP address")
local f_dev_port        = ProtoField.uint16("broadlink.flags.dev_port", "Port")
local f_dev_clientid    = ProtoField.uint16("broadlink.flags.dev_clientid", "ClientID")



local f_hello_timezone  = ProtoField.uint8("broadlink.flags.hello_tz", "Timezone")
local f_hello_year      = ProtoField.uint8("broadlink.flags.hello_year", "Year")
local f_hello_sec       = ProtoField.uint8("broadlink.flags.hello_sec", "Sec")
local f_hello_min       = ProtoField.uint8("broadlink.flags.hello_min", "Min")
local f_hello_hour      = ProtoField.uint8("broadlink.flags.hello_hour", "Hour")
local f_hello_day       = ProtoField.uint8("broadlink.flags.hello_day", "Day")
local f_hello_dayofweek = ProtoField.uint8("broadlink.flags.hello_dayofweek", "Day of week")
local f_hello_month     = ProtoField.uint8("broadlink.flags.hello_month", "Month")

local f_message_idx          = ProtoField.uint8("broadlink.flags.message_idx", "Message counter")
local f_message_chksum       = ProtoField.uint8("broadlink.flags.message_chksum", "Message Checksum", base.HEX)
local f_message_chksump      = ProtoField.uint8("broadlink.flags.message_chksump", "Payload Checksum", base.HEX)
local f_message_payloadenc_b = ProtoField.bytes("broadlink.flags.message_payloadenc_b", "Encrypted Payload")
local f_message_payloaddec_b = ProtoField.bytes("broadlink.flags.message_payloaddec_b", "Decrypted Payload")
local f_message_payloaddec_s = ProtoField.string("broadlink.flags.message_payloadec_s", "Decrypted Payload String")
local f_message_raw          = ProtoField.bytes("broadlink.flags.message_raw", "Raw bytes")

local f_decr_length          = ProtoField.uint8("broadlink.flags.decr_length", "Payload length")
local f_decr_cmdtype         = ProtoField.uint8("broadlink.flags.decr_cmdtype", "Command type", base.HEX, rcmdstate )
local f_decr_clength         = ProtoField.uint8("broadlink.flags.decr_clength", "Command length")
local f_decr_command         = ProtoField.string("broadlink.flags.decr_command", "Command")
local f_decr_authstatus      = ProtoField.uint16("broadlink.flags.decr_authstatus", "Auth status", base.HEX)
local f_decr_aeskey          = ProtoField.bytes("broadlink.flags.decr_aeskey", "AES128 key")
local f_decr_authstr1        = ProtoField.stringz("broadlink.flags.decr_authstr1", "Auth String1")
local f_decr_authstr2        = ProtoField.stringz("broadlink.flags.decr_authstr2", "Auth String2")
local f_decr_authstr3        = ProtoField.stringz("broadlink.flags.decr_authstr3", "Auth String3")
local f_decr_aesalt          = ProtoField.bytes("broadlink.flags.decr_aesalt", "Alt AES key?")


broadlink.fields = { f_command, f_dev_type, f_dev_mac, f_dev_name, f_dev_ip, f_dev_port, f_dev_clientid, 
                     f_hello_timezone, f_hello_year, f_hello_sec, f_hello_min, f_hello_hour, f_hello_day, f_hello_dayofweek, f_hello_month,
                     f_message_idx, f_message_chksum, f_message_chksump, f_message_payloadenc_b, f_message_payloaddec_b, f_message_payloaddec_s, f_message_raw,
                     f_decr_length, f_decr_cmdtype, f_decr_clength, f_decr_command, f_decr_authstatus, f_decr_aeskey, f_decr_authstr1, f_decr_authstr2, f_decr_authstr3, f_decr_aesalt }


-- create a function to dissect it
function broadlink.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "Broadlink"
    local subtree = tree:add(broadlink,buffer(),"Broadlink Protocol Data")
    subtree:add(buffer(0,8),"Connection ID: 0x" .. tostring(buffer(0,8)))
    subtree:add_le(f_message_raw, buffer())
    subtree:add_le(f_command, buffer(0x26,2))
    pcommand = buffer(0x26,2):le_uint()
    if  pcommand== 0x06 then
        timetree = subtree:add(buffer(0x08,12),"Device time")
        timetree:add_le(f_hello_timezone,buffer(0x08,4))
        timetree:add_le(f_hello_year,buffer(0x0c,2))
        timetree:add_le(f_hello_month,buffer(0x13,1))
        timetree:add_le(f_hello_day,buffer(0x12,1))
        timetree:add_le(f_hello_dayofweek,buffer(0x11,1))
        timetree:add_le(f_hello_hour,buffer(0x10,1))
        timetree:add_le(f_hello_min,buffer(0x0f,1))
        timetree:add_le(f_hello_sec,buffer(0x0e,1))
        subtree:add_le(f_dev_ip,buffer(0x18,4))
        subtree:add_le(f_dev_port,buffer(0x1C,4))
    elseif pcommand == 0x07 then
        subtree:add(f_dev_type,buffer(0x34,2))
        subtree:add_le(f_dev_mac,buffer(0x3A,6))
        subtree:add_le(f_dev_ip,buffer(0x36,4))
        subtree:add(f_dev_name,buffer(0x40))
    elseif pcommand == 0x6a or pcommand == 0x3ee or pcommand == 0x65 or pcommand == 0x3e9 then
        subtree:add_le(f_dev_type,buffer(0x24,2))
        subtree:add_le(f_message_chksum,buffer(0x20,2))
        subtree:add_le(f_message_idx,buffer(0x28,2))
        subtree:add_le(f_dev_mac,buffer(0x2A,6))
        subtree:add_le(f_dev_clientid,buffer(0x30,4))
        subtree:add_le(f_message_chksump,buffer(0x34,2))

        if buffer():len()-0x38 <= 0 then
            subtree:add("Encrypted data length: " .. buffer():len()-0x38)
        else
            subtree:add("Encrypted data: " .. buffer(0x38))

            -- Decrypt content.
            local cipher = gcrypt.Cipher(gcrypt.CIPHER_AES128, gcrypt.CIPHER_MODE_CBC)
            if not pcall(function()
                -- auth request (0x65) and response (0x3e9) uses the default AES128 key 
                if pcommand == 0x65 or pcommand == 0x3e9 then
                    cipher:setkey(fromhex(default_settings.aes_defkey))
                else
                    cipher:setkey(fromhex(broadlink.prefs.aes_key))
                end
                cipher:setiv(fromhex("562e17996d093d28ddb3ba695a2e6f58"))
            end) then
                subtree:add("Invalid decryption key set in protocol preferences.")
            end

            if not pcall(function()
                decrypted = cipher:decrypt(fromhex(tostring(buffer(0x38):bytes())))
                local buff = ByteArray.new(Struct.tohex(decrypted))
                local bufFrame = ByteArray.tvb(buff, "Decrypted buffer")
                decrtree = subtree:add(bufFrame(),"Decrypted payload")
                decrtree:add(f_message_payloaddec_b, bufFrame() )
                if pcommand == 0x3e9 then
                    decrtree:add_le(f_decr_authstatus, bufFrame(0x00,4))
                    decrtree:add(f_decr_aeskey,bufFrame(0x04,16))
                elseif pcommand == 0x65 then
                    decrtree:add(f_decr_authstr1, bufFrame(0x04,40))
                    decrtree:add(f_decr_authstr2, bufFrame(0x30,32))
                    decrtree:add(f_decr_authstr3, bufFrame(0x64))
                    decrtree:add(f_decr_aesalt, bufFrame(0x54,16))
                else
                    decrtree:add_le(f_decr_length, bufFrame(0x00,2))
                    decrtree:add(buffer(0,8),"Connection ID: 0x" .. tostring(bufFrame(0x02,4)))
                    decrtree:add_le(f_message_chksump,bufFrame(0x06,2))
                    decrtree:add(f_decr_cmdtype, bufFrame(0x08,1))
                    decrtree:add_le(f_decr_clength, bufFrame(0x0a,2))
                    decrtree:add(f_decr_command, bufFrame(0x0e))
                end
            end) then
                subtree:add("Unable to decrypt")
            end            

        end
    end
    
end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
udp_table:add(default_settings.port,broadlink)
