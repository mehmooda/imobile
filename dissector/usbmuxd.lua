local p_usbmuxd = Proto("usbmuxd", "USBMUX")
local protoHeader = p_usbmuxd.fields

local usbbus = Field.new("usb.bus_id")
local usbaddress = Field.new("usb.device_address")
local usbendpoint = Field.new("usb.endpoint_address.direction")
protoHeader.protocol = ProtoField.uint32("usbmuxd.protocol")
protoHeader.length = ProtoField.uint32("usbmuxd.length")

function p_usbmuxd.dissector(tvbuf, pktinfo, root)
    if tvbuf:len() < 8 then
        return
    end
    pktinfo.cols.protocol = p_usbmuxd.name
    --ONLY SUPPORT TCP
    if tvbuf(0, 4):int() ~= 6 then
        return
    end
    --FAKE IP ADDRESS
    local b = ByteArray.new("4500000000000000800600007f0000017f000001")
    if usbendpoint()() == 0 then
        b:set_index(18, usbbus()())
        b:set_index(19, usbaddress()())
    else
        b:set_index(14, usbbus()())
        b:set_index(15, usbaddress()())
    end
    local t = ByteArray.tvb(b, "FAKE_IP")
    local ip = Dissector.get("ip")
    ip:call(t, pktinfo, root)
    -- Add USBMUXD
    local sroot = root:add(p_usbmuxd, tvbuf(0, 8))
    sroot:add(p_usbmuxd.fields.protocol, tvbuf(0, 4))
    sroot:add(p_usbmuxd.fields.length, tvbuf(4, 4))
    local tcp = Dissector.get("tcp")
    tcp:call(tvbuf(8):tvb(), pktinfo, root)
end

DissectorTable.get("usb.product"):add(0x05ac12a8, p_usbmuxd)
DissectorTable.get("usb.device"):add("", p_usbmuxd)
local p_lockdownd = Proto("lockdownd", "Lockdownd")
local protoHeader = p_lockdownd.fields

protoHeader.message_length = ProtoField.uint32("lockdownd.message_length")

function p_lockdownd.dissector(tvbuf, pktinfo, root)
    local pass_to_ssl = nil
    local offset = pktinfo.desegment_offset or 0
    while offset < tvbuf:len() do
        local remaining = tvbuf:len() - offset
        if remaining < 4 then
            pktinfo.desegment_offset = offset
            pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            if pass_to_ssl ~= nil then
                Dissector.get("ssl"):call(tvbuf(pass_to_ssl, offset - pass_to_ssl):tvb(), pktinfo, root)
            end
            return
        end
        local mlen = tvbuf(offset, 4):uint() + 4
        if mlen > 0x10000000 then
            if remaining < 5 then
                pktinfo.desegment_offset = offset
                pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
                if pass_to_ssl ~= nil then
                    Dissector.get("ssl"):call(tvbuf(pass_to_ssl, offset - pass_to_ssl):tvb(), pktinfo, root)
                end
                return
            end
            mlen = tvbuf(offset + 3, 2):uint() + 5
            if remaining < mlen then
                pktinfo.desegment_offset = offset
                pktinfo.desegment_len = mlen - remaining
                if pass_to_ssl ~= nil then
                    Dissector.get("ssl"):call(tvbuf(pass_to_ssl, offset - pass_to_ssl):tvb(), pktinfo, root)
                end
                return
            end
            if pass_to_ssl == nil then
                pass_to_ssl = offset
            end
        else
            if pass_to_ssl ~= nil then
                local ssl = Dissector.get("ssl")
                ssl:call(tvbuf(pass_to_ssl, offset - pass_to_ssl):tvb(), pktinfo, root)
            end
            if mlen > remaining then
                pktinfo.desegment_offset = offset
                pktinfo.desegment_len = mlen - remaining
                if pass_to_ssl ~= nil then
                    Dissector.get("ssl"):call(tvbuf(pass_to_ssl, offset - pass_to_ssl):tvb(), pktinfo, root)
                end
                return
            end
            local sroot = root:add(p_lockdownd, tvbuf(offset, mlen))
            sroot:add(p_lockdownd.fields.message_length, tvbuf(offset, 4))
            local xml = Dissector.get("xml")
            xml:call(tvbuf(offset + 4, mlen - 4):tvb(), pktinfo, sroot)
            pktinfo.cols.protocol = p_lockdownd.name
            local xmlt = load_xml(tvbuf:raw(offset + 4, mlen - 4))
            if xmlt and xmlt.plist and xmlt.plist.dict then
                local v = DictGet(xmlt.plist.dict, "Request")
                pktinfo.cols.info = v
                if v == "QueryType" then
                    local v = DictGet(xmlt.plist.dict, "Type")
                    if v then
                        pktinfo.cols.info = tostring(pktinfo.cols.info) .. " = " .. v
                    end
                elseif v == "StartSession" then
                    local v = DictGet(xmlt.plist.dict, "EnableSessionSSL")
                    if v then
                        pktinfo.cols.info = tostring(pktinfo.cols.info) .. " SSL " .. v
                    end
                elseif v == "GetValue" then
                    local d = DictGet(xmlt.plist.dict, "Domain")
                    local k = DictGet(xmlt.plist.dict, "Key")
                    local v = DictGet(xmlt.plist.dict, "Value")
                    if k then
                        pktinfo.cols.info = tostring(pktinfo.cols.info) .. " " .. k
                    end
                    if v then
                        pktinfo.cols.info = tostring(pktinfo.cols.info) .. " = " .. v
                    end
                elseif v == "StartService" then
                    local Service = DictGet(xmlt.plist.dict, "Service")
                    local Port = DictGet(xmlt.plist.dict, "Port")
                    local SSL = DictGet(xmlt.plist.dict, "EnableServiceSSL")
                    if Service then
                        pktinfo.cols.info = tostring(pktinfo.cols.info) .. " " .. Service
                    end
                    if Port then
                        pktinfo.cols.info = tostring(pktinfo.cols.info) .. " Port " .. Port
                        local handle_proto
                        if Service == "com.apple.afc" then
                            handle_proto = p_afc
                        end
                        if SSL == "true" then
                            DissectorTable.get("tcp.port"):add(Port, Dissector.get("ssl"))
                        end
                        if handle_proto then
                            if SSL == "true" then
                                DissectorTable.get("ssl.port"):add(Port, handle_proto)
                            else
                                DissectorTable.get("tcp.port"):add(Port, handle_proto)
                            end
                        end
                    end
                    if SSL then
                        pktinfo.cols.info = tostring(pktinfo.cols.info) .. " SSL " .. SSL
                    end
                end
            end
        end
        offset = offset + mlen
        if pass_to_ssl ~= nil and offset == tvbuf:len() then
            Dissector.get("ssl"):call(tvbuf(pass_to_ssl, offset - pass_to_ssl):tvb(), pktinfo, root)
        end
    end
    return offset
end

function load_xml(data)
    local xml = XMLnewParser()
    local xmlt = xml:ParseXmlText(data)
    return xmlt
end

function log_tags(data)
    xmlt = load_xml(data)
    if xmlt and xmlt.plist and xmlt.plist.dict then
        for b, v in pairs(xmlt.plist.dict:children()) do
            info(v:name())
            info(v:value())
        end
    end
end

function DictGet(xmlt, thing)
    if xmlt:name() ~= "dict" then
        return nil
    end
    local c = xmlt:children()
    for b, v in pairs(c) do
        if v:name() == "key" and v:value() == thing then
            r = c[b + 1]
            if r:name() == "string" then
                return r:value()
            elseif r:name() == "integer" then
                return r:value()
            elseif r:name() == "true" then
                return "true"
            elseif r:name() == "false" then
                return "false"
            else
                return r:name()
            end
        end
    end
    return nil
end

DissectorTable.get("tcp.port"):add(62078, p_lockdownd)
DissectorTable.get("ssl.port"):add(62078, p_lockdownd)

p_afc = Proto("AFC", "Apple File Conduit")
local protoHeader = p_afc.fields
protoHeader.magic = ProtoField.string("afc.magic", "CFA6LPAA Magic")
protoHeader.alen = ProtoField.uint64("afc.alen", "Total Length")
protoHeader.tlen = ProtoField.uint64("afc.tlen", "Header Length")
protoHeader.pktnum = ProtoField.uint64("afc.pktnum", "Packet Number")
local op_field_values = {
    [0x00] = "Invalid",
    [0x01] = "Status",
    [0x02] = "Data",
    [0x03] = "ReadDir",
    [0x04] = "ReadFile",
    [0x05] = "WriteFile",
    [0x06] = "WritePart",
    [0x07] = "TruncateFile",
    [0x08] = "RemovePath",
    [0x09] = "MakeDir",
    [0x0A] = "GetFileInfo",
    [0x0B] = "GetDeviceInfo",
    [0x0C] = "WriteFileAtomic (tmp file+rename)",
    [0x0D] = "FileRefOpen",
    [0x0E] = "FileRefOpenResult",
    [0x0F] = "FileRefRead",
    [0x10] = "FileRefWrite",
    [0x11] = "FileRefSeek",
    [0x12] = "FileRefTell",
    [0x13] = "FileRefTellResult",
    [0x14] = "FileRefClose",
    [0x15] = "FileRefSetFileSize (ftruncate)",
    [0x16] = "GetConnectionInfo",
    [0x17] = "SetConnectionOptions",
    [0x18] = "RenamePath",
    [0x19] = "SetFSBlockSize (0x800000)",
    [0x1A] = "SetSocketBlockSize (0x800000)",
    [0x1B] = "FileRefLock",
    [0x1C] = "MakeLink",
    [0x1D] = "GetFileHash",
    [0x1E] = "SetModTime",
    [0x1F] = "GetFileHashWithRange",
    [0x20] = "FileRefSetImmutableHint",
    [0x21] = "GetSizeOfPathContents",
    [0x22] = "RemovePathAndContents",
    [0x23] = "DirectoryEnumeratorRefOpen",
    [0x24] = "DirectoryEnumeratorRefOpenResult",
    [0x25] = "DirectoryEnumeratorRefRead",
    [0x26] = "DirectoryEnumeratorRefClose",
    [0x27] = "FileRefReadWithOffset",
    [0x28] = "FileRefWriteWithOffset"
}
protoHeader.op = ProtoField.uint64("afc.op", "Operation", nil, op_field_values, nil, nil)
protoHeader.data = ProtoField.bytes("afc.data", "Header")

function p_afc.dissector(tvbuf, pktinfo, root)
    local offset = pktinfo.desegment_offset or 0
    while tvbuf:len() > offset do
        local remaining = tvbuf:len() - offset
        if remaining < 16 then
            pktinfo.desegment_offset = offset
            pktinfo.desegment_len = DESEGMENT_ONE_MORE_SEGMENT
            return
        end
        local mlen = tvbuf(offset + 8, 4):le_uint()
        if remaining < mlen then
            pktinfo.desegment_offset = offset
            pktinfo.desegment_len = mlen - remaining
            return
        end
        local tlen = tvbuf(offset + 16, 4):le_uint()
        local sroot = root:add(p_afc, tvbuf(offset, tlen))
        sroot:add(p_afc.fields.magic, tvbuf(offset, 8))
        sroot:add_le(p_afc.fields.alen, tvbuf(offset + 8, 8))
        sroot:add_le(p_afc.fields.tlen, tvbuf(offset + 16, 8))
        sroot:add_le(p_afc.fields.pktnum, tvbuf(offset + 24, 8))
        sroot:add_le(p_afc.fields.op, tvbuf(offset + 32, 8))
        if tlen > 40 then
            sroot:add(p_afc.fields.data, tvbuf(offset + 40, tlen - 40))
        end
        if mlen > tlen then
            root:add("DATA", tvbuf(offset + tlen, mlen - tlen))
        end
        pktinfo.cols.protocol = p_afc.name
        pktinfo.cols.info = op_field_values[tvbuf(offset + 32, 4):le_uint()]
        offset = offset + mlen
    end
end

DissectorTable.get("tcp.port"):add("", p_afc)
DissectorTable.get("ssl.port"):add("", p_afc)

---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
--
-- xml.lua - XML parser for use with the Corona SDK.
--
-- version: 1.2
--
-- CHANGELOG:
--
-- 1.2 - Created new structure for returned table
-- 1.1 - Fixed base directory issue with the loadFile() function.
--
-- NOTE: This is a modified version of Alexander Makeev's Lua-only XML parser
-- found here: http://lua-users.org/wiki/LuaXml
--
---------------------------------------------------------------------------------
---------------------------------------------------------------------------------
function XMLnewParser()
    XmlParser = {}

    function XmlParser:ToXmlString(value)
        value = string.gsub(value, "&", "&amp;") -- '&' -> "&amp;"
        value = string.gsub(value, "<", "&lt;") -- '<' -> "&lt;"
        value = string.gsub(value, ">", "&gt;") -- '>' -> "&gt;"
        value = string.gsub(value, '"', "&quot;") -- '"' -> "&quot;"
        value =
            string.gsub(
            value,
            "([^%w%&%;%p%\t% ])",
            function(c)
                return string.format("&#x%X;", string.byte(c))
            end
        )
        return value
    end

    function XmlParser:FromXmlString(value)
        value =
            string.gsub(
            value,
            "&#x([%x]+)%;",
            function(h)
                return string.char(tonumber(h, 16))
            end
        )
        value =
            string.gsub(
            value,
            "&#([0-9]+)%;",
            function(h)
                return string.char(tonumber(h, 10))
            end
        )
        value = string.gsub(value, "&quot;", '"')
        value = string.gsub(value, "&apos;", "'")
        value = string.gsub(value, "&gt;", ">")
        value = string.gsub(value, "&lt;", "<")
        value = string.gsub(value, "&amp;", "&")
        return value
    end

    function XmlParser:ParseArgs(node, s)
        string.gsub(
            s,
            '(%w+)=(["\'])(.-)%2',
            function(w, _, a)
                node:addProperty(w, self:FromXmlString(a))
            end
        )
    end

    function XmlParser:ParseXmlText(xmlText)
        local stack = {}
        local top = newNode()
        table.insert(stack, top)
        local ni, c, label, xarg, empty
        local i, j = 1, 1
        while true do
            ni, j, c, label, xarg, empty = string.find(xmlText, "<(%/?)([%w_:]+)(.-)(%/?)>", i)
            if not ni then
                break
            end
            local text = string.sub(xmlText, i, ni - 1)
            if not string.find(text, "^%s*$") then
                local lVal = (top:value() or "") .. self:FromXmlString(text)
                stack[#stack]:setValue(lVal)
            end
            if empty == "/" then -- empty element tag
                local lNode = newNode(label)
                self:ParseArgs(lNode, xarg)
                top:addChild(lNode)
            elseif c == "" then -- start tag
                local lNode = newNode(label)
                self:ParseArgs(lNode, xarg)
                table.insert(stack, lNode)
                top = lNode
            else -- end tag
                local toclose = table.remove(stack) -- remove top

                top = stack[#stack]
                if #stack < 1 then
                    error("XmlParser: nothing to close with " .. label)
                end
                if toclose:name() ~= label then
                    error("XmlParser: trying to close " .. toclose.name .. " with " .. label)
                end
                top:addChild(toclose)
            end
            i = j + 1
        end
        local text = string.sub(xmlText, i)
        if #stack > 1 then
            error("XmlParser: unclosed " .. stack[#stack]:name())
        end
        return top
    end

    function XmlParser:loadFile(xmlFilename, base)
        if not base then
            base = system.ResourceDirectory
        end

        local path = system.pathForFile(xmlFilename, base)
        local hFile, err = io.open(path, "r")

        if hFile and not err then
            local xmlText = hFile:read("*a") -- read file content
            io.close(hFile)
            return self:ParseXmlText(xmlText), nil
        else
            print(err)
            return nil
        end
    end

    return XmlParser
end

function newNode(name)
    local node = {}
    node.___value = nil
    node.___name = name
    node.___children = {}
    node.___props = {}

    function node:value()
        return self.___value
    end
    function node:setValue(val)
        self.___value = val
    end
    function node:name()
        return self.___name
    end
    function node:setName(name)
        self.___name = name
    end
    function node:children()
        return self.___children
    end
    function node:numChildren()
        return #self.___children
    end
    function node:addChild(child)
        if self[child:name()] ~= nil then
            if type(self[child:name()].name) == "function" then
                local tempTable = {}
                table.insert(tempTable, self[child:name()])
                self[child:name()] = tempTable
            end
            table.insert(self[child:name()], child)
        else
            self[child:name()] = child
        end
        table.insert(self.___children, child)
    end

    function node:properties()
        return self.___props
    end
    function node:numProperties()
        return #self.___props
    end
    function node:addProperty(name, value)
        local lName = "@" .. name
        if self[lName] ~= nil then
            if type(self[lName]) == "string" then
                local tempTable = {}
                table.insert(tempTable, self[lName])
                self[lName] = tempTable
            end
            table.insert(self[lName], value)
        else
            self[lName] = value
        end
        table.insert(self.___props, {name = name, value = self[name]})
    end

    return node
end
