--- Configuration module for ClaudeAutoAllow
--- Handles default settings and persistence

local M = {}

-- Default configuration
M.DEFAULTS = {
    -- Core functionality
    enabled = true,

    -- Target applications (terminal emulators + Claude desktop app)
    targetApps = {
        "Claude",
        "Terminal",
        "iTerm2",
        "iTerm",
        "Warp",
        "kitty",
        "Alacritty",
        "Ghostty",
        "Hyper",
        "WezTerm",
        "Rio",
        "Tabby",
    },

    -- Timing
    debounceMs = 300,           -- Minimum ms between clicks
    pollIntervalSec = 0.5,      -- Backup polling interval
    uiRenderDelayMs = 100,      -- Wait for UI to render after event

    -- Feedback
    soundEnabled = false,       -- Play sound on click (subtle "Pop")
    alertEnabled = true,        -- Show brief on-screen alert
    alertDurationSec = 1,       -- How long alert stays on screen

    -- Menubar
    showMenubar = true,         -- Show menubar icon
    showClickCount = false,     -- Show click count in menubar title

    -- Logging
    logEnabled = true,          -- Write to audit log file
    maxLogLines = 1000,         -- Max lines in log file
    maxRecentActions = 50,      -- Max actions in memory

    -- Safety (these merge with safety.lua lists)
    customAllowedButtons = {},  -- Additional buttons to allow
    strictMode = false,         -- If true, require context validation

    -- Advanced
    maxSearchDepth = 15,         -- How deep to search UI tree
}

-- Settings key for persistence
local SETTINGS_KEY = "ClaudeAutoAllow"
local WELCOMED_KEY = "ClaudeAutoAllow_welcomed"
local STATS_KEY = "ClaudeAutoAllow_stats"

--- Deep merge two tables (b overrides a)
local function deepMerge(a, b)
    local result = {}
    for k, v in pairs(a) do
        result[k] = v
    end
    for k, v in pairs(b) do
        if type(v) == "table" and type(result[k]) == "table" then
            result[k] = deepMerge(result[k], v)
        else
            result[k] = v
        end
    end
    return result
end

--- Load configuration from persistent storage
--- @return table config The merged configuration
function M.load()
    local saved = hs.settings.get(SETTINGS_KEY) or {}
    return deepMerge(M.DEFAULTS, saved)
end

--- Save configuration to persistent storage
--- @param config table The configuration to save
function M.save(config)
    -- Only save non-default values to keep storage clean
    local toSave = {}
    for k, v in pairs(config) do
        if M.DEFAULTS[k] ~= v then
            toSave[k] = v
        end
    end
    hs.settings.set(SETTINGS_KEY, toSave)
end

--- Reset configuration to defaults
function M.reset()
    hs.settings.set(SETTINGS_KEY, {})
end

--- Check if this is the first run
--- @return boolean
function M.isFirstRun()
    return not hs.settings.get(WELCOMED_KEY)
end

--- Mark first run as complete
function M.markWelcomed()
    hs.settings.set(WELCOMED_KEY, true)
end

--- Load statistics
--- @return table stats
function M.loadStats()
    return hs.settings.get(STATS_KEY) or {
        total = 0,
        today = 0,
        todayDate = os.date("%Y-%m-%d"),
        lastAction = nil,
        lastActionTime = nil,
    }
end

--- Save statistics
--- @param stats table
function M.saveStats(stats)
    hs.settings.set(STATS_KEY, stats)
end

--- Increment click count
--- @param stats table Current stats
--- @param buttonTitle string What was clicked
--- @return table Updated stats
function M.incrementStats(stats, buttonTitle)
    local today = os.date("%Y-%m-%d")

    -- Reset daily count if new day
    if stats.todayDate ~= today then
        stats.today = 0
        stats.todayDate = today
    end

    stats.total = (stats.total or 0) + 1
    stats.today = (stats.today or 0) + 1
    stats.lastAction = buttonTitle
    stats.lastActionTime = os.date("%H:%M:%S")

    M.saveStats(stats)
    return stats
end

return M
