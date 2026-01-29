--- === ClaudeAutoAllow ===
---
--- Automatically clicks "Allow" and "Yes" buttons in Claude Code permission dialogs.
---
--- This Spoon monitors terminal applications for permission prompts and auto-clicks
--- safe buttons while maintaining a strict blocklist for dangerous actions.
---
--- Download: https://github.com/mattbeane/ClaudeAutoAllow
---
--- Usage:
--- ```lua
--- hs.loadSpoon("ClaudeAutoAllow")
--- spoon.ClaudeAutoAllow:start()
---
--- -- Optional: bind a hotkey to toggle
--- spoon.ClaudeAutoAllow:bindHotkeys({
---     toggle = {{"cmd", "shift"}, "A"}
--- })
--- ```

local obj = {}
obj.__index = obj

-- Spoon metadata
obj.name = "ClaudeAutoAllow"
obj.version = "1.0.0"
obj.author = "Matt Beane <matt@mattbeane.com>"
obj.homepage = "https://github.com/mattbeane/ClaudeAutoAllow"
obj.license = "MIT - https://opensource.org/licenses/MIT"

-- Spoon path (set automatically when loaded)
obj.spoonPath = nil

-- State
obj.enabled = false
obj.config = nil
obj.stats = nil
obj.hotkey = nil

-- Logger (debug level to see button detection)
obj.logger = hs.logger.new("ClaudeAutoAllow", "debug")

-- Load submodules (relative to spoon path)
local safety, configMod, ui, core

--- ClaudeAutoAllow:init()
--- Method
--- Initialize the spoon. Called automatically by hs.loadSpoon().
function obj:init()
    -- Determine spoon path
    self.spoonPath = hs.spoons.scriptPath()

    -- Load submodules
    local function loadModule(name)
        local path = self.spoonPath .. "/" .. name .. ".lua"
        local fn, err = loadfile(path)
        if not fn then
            self.logger.e("Failed to load " .. name .. ": " .. tostring(err))
            return nil
        end
        return fn()
    end

    safety = loadModule("safety")
    configMod = loadModule("config")
    ui = loadModule("ui")
    core = loadModule("core")

    if not (safety and configMod and ui and core) then
        self.logger.e("Failed to load required modules")
        return self
    end

    -- Load configuration and stats
    self.config = configMod.load()
    self.stats = configMod.loadStats()

    -- Initialize core with dependencies
    core.init(self, {
        safety = safety,
        ui = ui,
        config = configMod,
    })

    return self
end

--- ClaudeAutoAllow:start()
--- Method
--- Start monitoring for permission dialogs.
---
--- Returns:
---  * The ClaudeAutoAllow object
function obj:start()
    -- Check accessibility permissions
    if not hs.accessibilityState() then
        hs.alert.show(
            "Claude Auto-Allow needs Accessibility permissions.\n" ..
            "Opening System Settings...",
            5
        )
        -- Try to open the right pane
        hs.execute("open 'x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility'")
        return self
    end

    -- Show welcome on first run
    if configMod.isFirstRun() then
        ui.showWelcome()
        configMod.markWelcomed()
    end

    -- Set up UI
    ui.setupMenubar(self)

    -- Set up watchers
    core.setupWatchers()

    -- Enable
    self.enabled = true
    ui.updateMenubarIcon()

    -- Enable hotkey if bound
    if self.hotkey then
        self.hotkey:enable()
    end

    self.logger.i("ClaudeAutoAllow started")
    hs.alert.show("Claude Auto-Allow active", 1.5)

    return self
end

--- ClaudeAutoAllow:stop()
--- Method
--- Stop monitoring for permission dialogs.
---
--- Returns:
---  * The ClaudeAutoAllow object
function obj:stop()
    self.enabled = false

    -- Clean up
    core.cleanup()
    ui.cleanup()

    -- Disable hotkey
    if self.hotkey then
        self.hotkey:disable()
    end

    self.logger.i("ClaudeAutoAllow stopped")

    return self
end

--- ClaudeAutoAllow:toggle()
--- Method
--- Toggle monitoring on/off.
---
--- Returns:
---  * The ClaudeAutoAllow object
function obj:toggle()
    if self.enabled then
        self.enabled = false
        ui.updateMenubarIcon()
        ui.showAlert("Claude Auto-Allow paused", 1)
        self.logger.i("Paused")
    else
        self.enabled = true
        ui.updateMenubarIcon()
        ui.showAlert("Claude Auto-Allow resumed", 1)
        self.logger.i("Resumed")
    end
    return self
end

--- ClaudeAutoAllow:bindHotkeys(mapping)
--- Method
--- Bind hotkeys to control ClaudeAutoAllow.
---
--- Parameters:
---  * mapping - A table with keys:
---    * toggle - Hotkey to toggle on/off, e.g. {{"cmd", "shift"}, "A"}
---
--- Returns:
---  * The ClaudeAutoAllow object
function obj:bindHotkeys(mapping)
    if mapping.toggle then
        self.hotkey = hs.hotkey.new(
            mapping.toggle[1],
            mapping.toggle[2],
            function() self:toggle() end
        )
        -- Enable if already started
        if self.enabled then
            self.hotkey:enable()
        end
    end
    return self
end

--- ClaudeAutoAllow:scanNow()
--- Method
--- Manually trigger a scan of all target app windows.
--- Useful for debugging or forcing a check.
---
--- Returns:
---  * true if a button was clicked, false otherwise
function obj:scanNow()
    return core.scanAllWindows()
end

--- ClaudeAutoAllow:addAllowedButton(buttonTitle)
--- Method
--- Add a button title to the custom allowlist.
---
--- Parameters:
---  * buttonTitle - The button title to allow
---
--- Returns:
---  * The ClaudeAutoAllow object
function obj:addAllowedButton(buttonTitle)
    self.config.customAllowedButtons = self.config.customAllowedButtons or {}
    table.insert(self.config.customAllowedButtons, buttonTitle)
    configMod.save(self.config)
    self.logger.i("Added to allowlist: " .. buttonTitle)
    return self
end

--- ClaudeAutoAllow:removeAllowedButton(buttonTitle)
--- Method
--- Remove a button title from the custom allowlist.
---
--- Parameters:
---  * buttonTitle - The button title to remove
---
--- Returns:
---  * The ClaudeAutoAllow object
function obj:removeAllowedButton(buttonTitle)
    if not self.config.customAllowedButtons then return self end

    for i, btn in ipairs(self.config.customAllowedButtons) do
        if btn == buttonTitle then
            table.remove(self.config.customAllowedButtons, i)
            configMod.save(self.config)
            self.logger.i("Removed from allowlist: " .. buttonTitle)
            break
        end
    end
    return self
end

--- ClaudeAutoAllow:setTargetApps(apps)
--- Method
--- Set the list of terminal apps to monitor.
---
--- Parameters:
---  * apps - A table of application names, e.g. {"Terminal", "iTerm2"}
---
--- Returns:
---  * The ClaudeAutoAllow object
function obj:setTargetApps(apps)
    self.config.targetApps = apps
    configMod.save(self.config)

    -- Restart watchers if running
    if self.enabled then
        core.cleanup()
        core.setupWatchers()
    end

    return self
end

return obj
