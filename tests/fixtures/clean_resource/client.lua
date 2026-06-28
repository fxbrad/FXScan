local function greet(name)
    print('hello ' .. name)
end

RegisterNetEvent('clean:greet')
AddEventHandler('clean:greet', function(name)
    greet(name)
end)
