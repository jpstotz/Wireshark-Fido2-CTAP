cbor = Dissector.get("cbor")
iso7816 = Dissector.get("iso7816")
ctap_proto = Proto("ctaphid","ctap hid")
-- Field Extractor
direction_fe = Field.new("usb.endpoint_address.direction")
udp_srcport_fe = Field.new("udp.srcport")

CTAPHID_COMMAND_CODE = {
    [0x03]='CTAPHID_MSG',
    [0x10]='CTAPHID_CBOR',
    [0x06]='CTAPHID_INIT',
    [0x01]='CTAPHID_PING',
    [0x11]='CTAPHID_CANCEL',
    [0x3F]='CTAPHID_ERROR',
    [0x3B]='CTAPHID_KEEPALIVE',
    [0x08]='CTAPHID_WINK',
    [0x04]='CTAPHID_LOCK',
}
CTAP_COMMAND_CODE = {
    [0x01]='authenticatorMakeCredential',
    [0x02]='authenticatorGetAssertion',
    [0x04]='authenticatorGetInfo',
    [0x06]='authenticatorClientPIN',
    [0x07]='authenticatorReset',
    [0x08]='authenticatorGetNextAssertion',
    [0x40]='authenticatorVendorFirst',
    [0xBF]='authenticatorVendorLast'
}
CTAP_RESPONSE_CODE = {
    [0x00]='CTAP1_ERR_SUCCESS',
    [0x01]='CTAP1_ERR_INVALID_COMMAND',
    [0x02]='CTAP1_ERR_INVALID_PARAMETER',
    [0x03]='CTAP1_ERR_INVALID_LENGTH',
    [0x04]='CTAP1_ERR_INVALID_SEQ',
    [0x05]='CTAP1_ERR_TIMEOUT',
    [0x06]='CTAP1_ERR_CHANNEL_BUSY',
    [0x0A]='CTAP1_ERR_LOCK_REQUIRED',
    [0x0B]='CTAP1_ERR_INVALID_CHANNEL',
    [0x11]='CTAP2_ERR_CBOR_UNEXPECTED_TYPE',
    [0x12]='CTAP2_ERR_INVALID_CBOR',
    [0x14]='CTAP2_ERR_MISSING_PARAMETER',
    [0x15]='CTAP2_ERR_LIMIT_EXCEEDED',
    [0x16]='CTAP2_ERR_UNSUPPORTED_EXTENSION',
    [0x19]='CTAP2_ERR_CREDENTIAL_EXCLUDED',
    [0x21]='CTAP2_ERR_PROCESSING',
    [0x22]='CTAP2_ERR_INVALID_CREDENTIAL',
    [0x23]='CTAP2_ERR_USER_ACTION_PENDING',
    [0x24]='CTAP2_ERR_OPERATION_PENDING',
    [0x25]='CTAP2_ERR_NO_OPERATIONS',
    [0x26]='CTAP2_ERR_UNSUPPORTED_ALGORITHM',
    [0x27]='CTAP2_ERR_OPERATION_DENIED',
    [0x28]='CTAP2_ERR_KEY_STORE_FULL',
    [0x29]='CTAP2_ERR_NOT_BUSY',
    [0x2A]='CTAP2_ERR_NO_OPERATION_PENDING',
    [0x2B]='CTAP2_ERR_UNSUPPORTED_OPTION',
    [0x2C]='CTAP2_ERR_INVALID_OPTION',
    [0x2D]='CTAP2_ERR_KEEPALIVE_CANCEL',
    [0x2E]='CTAP2_ERR_NO_CREDENTIALS',
    [0x2F]='CTAP2_ERR_USER_ACTION_TIMEOUT',
    [0x30]='CTAP2_ERR_NOT_ALLOWED',
    [0x31]='CTAP2_ERR_PIN_INVALID',
    [0x32]='CTAP2_ERR_PIN_BLOCKED',
    [0x33]='CTAP2_ERR_PIN_AUTH_INVALID',
    [0x34]='CTAP2_ERR_PIN_AUTH_BLOCKED',
    [0x35]='CTAP2_ERR_PIN_NOT_SET',
    [0x36]='CTAP2_ERR_PIN_REQUIRED',
    [0x37]='CTAP2_ERR_PIN_POLICY_VIOLATION',
    [0x38]='CTAP2_ERR_PIN_TOKEN_EXPIRED',
    [0x39]='CTAP2_ERR_REQUEST_TOO_LARGE',
    [0x3A]='CTAP2_ERR_ACTION_TIMEOUT',
    [0x3B]='CTAP2_ERR_UP_REQUIRED',
    [0x7F]='CTAP1_ERR_OTHER',
    [0xDF]='CTAP2_ERR_SPEC_LAST',
    [0xE0]='CTAP2_ERR_EXTENSION_FIRST',
    [0xEF]='CTAP2_ERR_EXTENSION_LAST',
    [0xF0]='CTAP2_ERR_VENDOR_FIRST',
    [0xFF]='CTAP2_ERR_VENDOR_LAST'
}

function payload_dissector(pinfo, subtree, state)
    local t = ByteArray.tvb(state.payload_buffer:subset(0, state.total_len), "payload")
    local isIN = 0
    local usb_dir = direction_fe()
    if usb_dir ~= nil then
        isIN = usb_dir.value
    else
        if tostring(udp_srcport_fe()) == "8111" then
            isIN = 1
        else
            isIN = 0
        end
    end
    -- pinfo.cols.protocol = tostring(udp_srcport_fe())

    if state.ctaphid_cmd == 0x10 then
        local subtree = subtree:add(t(0),"FIDO2 Payload")
        local ctap_cmd = t(0,1):uint();
        local text = ({[0]=CTAP_COMMAND_CODE, [1]=CTAP_RESPONSE_CODE})[isIN][ctap_cmd]
        pinfo.cols.protocol = "CTAP " .. text
        subtree:add(t(0,1),string.format('CTAP CMD/Status: %s (0x%02x)', text, ctap_cmd))
        if t(1):len() > 0 then
            cbor:call(t(1):tvb(), pinfo, subtree)
        end
    elseif state.ctaphid_cmd == 0x03 then
        local subtree = subtree:add(t(0),"FIDO/U2F Payload")
        iso7816:call(t, pinfo, subtree)
    else
        local subtree = subtree:add(t(0),"Other Payload")
    end
end

cached_info = {}
total_len = 0
ctaphid_cmd = 0
payload_buffer = nil

-- create a function to dissect it
function ctap_proto.dissector(buffer,pinfo,tree)
    pinfo.cols.protocol = "CTAPHID"
    local subtree = tree:add(ctap_proto,buffer(),"CTAPHID")
    local data = nil
    -- subtree:add(buffer,"length=" .. string.format('0x%08x',buffer:len()) .. " " .. direction_fe().value)
    local cid = buffer(0,4):uint()
    subtree:add(buffer(0,4),string.format('CID: 0x%08x',cid))
    local cmd = buffer(4,1):uint()
    if bit.band(cmd, 0x80) == 0x80 then
        ctaphid_cmd = bit.band(cmd, 0x7f)
        subtree:add(buffer(4,1),string.format('CMD: %s (0x%02x)',CTAPHID_COMMAND_CODE[ctaphid_cmd],ctaphid_cmd))

        total_len = buffer(5,2):uint()
        subtree:add(buffer(5,2),string.format('Length: 0x%04x',total_len))

        payload_buffer = ByteArray.new()
        data = buffer(7)
    else
        subtree:add(buffer(4,1),string.format('SEQ: 0x%02x',cmd))
        data = buffer(5)
    end

    local state = cached_info[pinfo.number]
    if state ~= nil then
        if state.ctaphid_cmd ~= nil then
            payload_dissector(pinfo, subtree, state)
        end
    else
        -- first interation
        state = {}
        payload_buffer:append(data:bytes())
        if payload_buffer:len() >= total_len then
            -- cache info for later display
            state.ctaphid_cmd = ctaphid_cmd
            state.payload_buffer = payload_buffer
            state.total_len = total_len

            payload_dissector(pinfo, subtree, state)
        end
        cached_info[pinfo.number] = state
    end
end
usb_table = DissectorTable.get("usb.product")
usb_table:add(0x10500407,ctap_proto) -- VID/PID of Yubikey
udp_table = DissectorTable.get("udp.port")
udp_table:add(8111,ctap_proto) -- Solokeys simulation
udp_table:add(7112,ctap_proto) -- Solokeys simulation