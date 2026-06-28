local players = {}

RegisterNetEvent('clean:join')
AddEventHandler('clean:join', function()
    local src = source
    players[src] = true
end)

AddEventHandler('playerDropped', function()
    players[source] = nil
end)
