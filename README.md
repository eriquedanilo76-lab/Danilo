-- AdminModule (ModuleScript)
local AdminModule = {}

-- CONFIG
AdminModule.OwnerUserId = 12345678 -- seu userId (owner)
AdminModule.AdminUserIds = {
    [12345678] = true, -- owner
    -- adicione outros IDs de admins aqui
}

AdminModule.CommandPrefix = "!"
AdminModule.BanDataStoreName = "AdminBansV2"

-- Dependências
local DataStoreService = game:GetService("DataStoreService")
AdminModule.BanStore = DataStoreService:GetDataStore(AdminModule.BanDataStoreName)

-- Helpers
local function isAdmin(userId)
    return AdminModule.AdminUserIds[userId] == true or userId == AdminModule.OwnerUserId
end

function AdminModule:SendLog(msg)
    print("[ADMIN LOG] "..msg)
    -- aqui você pode estender e salvar logs em DataStore/External
end

-- Ban management (in-memory cache + datastore)
AdminModule.bans = {} -- [userId] = {reason=..., expires=timestamp or nil}

function AdminModule:LoadBans()
    local ok, data = pcall(function()
        return self.BanStore:GetAsync("bans")
    end)
    if ok and type(data) == "table" then
        self.bans = data
    else
        self.bans = {}
    end
end

function AdminModule:SaveBans()
    local ok, err = pcall(function()
        self.BanStore:SetAsync("bans", self.bans)
    end)
    if not ok then
        warn("Failed to save bans:", err)
    end
end

function AdminModule:IsBanned(userId)
    local ban = self.bans[tostring(userId)]
    if not ban then return false end
    if ban.expires then
        if os.time() > ban.expires then
            -- expired
            self.bans[tostring(userId)] = nil
            self:SaveBans()
            return false
        end
    end
    return true, ban
end

function AdminModule:BanUser(userId, reason, durationSeconds)
    local key = tostring(userId)
    local banData = { reason = reason or "Banido pelo admin", created = os.time() }
    if durationSeconds and durationSeconds > 0 then
        banData.expires = os.time() + durationSeconds
    end
    self.bans[key] = banData
    self:SaveBans()
    self:SendLog(("User %s banned. Reason: %s. Duration: %s"):format(userId, banData.reason, banData.expires and tostring(durationSeconds).."s" or "permanent"))
end

function AdminModule:UnbanUser(userId)
    local key = tostring(userId)
    if self.bans[key] then
        self.bans[key] = nil
        self:SaveBans()
        self:SendLog(("User %s unbanned."):format(userId))
    end
end

-- Basic command parsing (server-side)
function AdminModule:ParseCommand(speaker, message)
    if not message then return end
    if type(message) ~= "string" then return end
    if not message:sub(1, #self.CommandPrefix) == self.CommandPrefix then return end
    -- remove prefix
    local body = message:sub(#self.CommandPrefix + 1)
    local parts = {}
    for token in string.gmatch(body, "%S+") do
        table.insert(parts, token)
    end
    local cmd = parts[1] and parts[1]:lower()
    if not cmd then return end
    table.remove(parts,1)
    return cmd, parts
end

return AdminModule
