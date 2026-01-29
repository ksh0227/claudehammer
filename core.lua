--- Core detection and clicking module for ClaudeAutoAllow
--- Handles watching for buttons and clicking them safely

local M = {}

-- File-based debug logging (since system log is hard to access)
local DEBUG_LOG_FILE = "/tmp/claude_auto_allow.log"
local function debugLog(msg)
    local f = io.open(DEBUG_LOG_FILE, "a")
    if f then
        f:write(os.date("%H:%M:%S") .. " " .. msg .. "\n")
        f:close()
    end
end

-- Module state
M.spoon = nil
M.windowFilter = nil
M.pollTimer = nil
M.appWatcher = nil
M.lastClickTime = 0
M.lastButtonCount = 0
M.stableHighCount = 0  -- Track the "normal" button count when no dialog

-- Dependencies (loaded in init)
local safety = nil
local ui = nil
local configMod = nil

--- Initialize core with dependencies
--- @param spoon table The main spoon object
--- @param deps table Dependencies {safety, ui, config}
function M.init(spoon, deps)
    M.spoon = spoon
    safety = deps.safety
    ui = deps.ui
    configMod = deps.config
end

--- Check if an app name is in the target list
--- @param appName string The application name
--- @return boolean
local function isTargetApp(appName)
    if not appName then return false end
    local config = M.spoon and M.spoon.config or {}
    local targets = config.targetApps or {}

    for _, target in ipairs(targets) do
        if appName == target then
            return true
        end
    end
    return false
end

--- Extract text from a button, trying multiple accessibility attributes
--- @param button userdata AX button element
--- @param log userdata Logger
--- @return string|nil title The button's text if found
--- @return table attrs All found attributes for debugging
local function extractButtonText(button, log)
    local attrs = {}

    -- Try standard attributes
    attrs.title = button:attributeValue("AXTitle")
    attrs.desc = button:attributeValue("AXDescription")
    attrs.identifier = button:attributeValue("AXIdentifier")
    attrs.value = button:attributeValue("AXValue")
    attrs.help = button:attributeValue("AXHelp")
    attrs.roleDesc = button:attributeValue("AXRoleDescription")
    attrs.label = button:attributeValue("AXLabel")

    -- Check for text in child elements (Electron often does this)
    local children = button:attributeValue("AXChildren")
    if children and #children > 0 then
        attrs.childCount = #children
        for i, child in ipairs(children) do
            local childRole = child:attributeValue("AXRole")
            local childValue = child:attributeValue("AXValue")
            local childTitle = child:attributeValue("AXTitle")
            local childDesc = child:attributeValue("AXDescription")

            if childRole == "AXStaticText" then
                attrs["child" .. i .. "_text"] = childValue or childTitle or childDesc
            end

            -- Also check grandchildren (nested text)
            local grandchildren = child:attributeValue("AXChildren")
            if grandchildren then
                for j, gc in ipairs(grandchildren) do
                    local gcRole = gc:attributeValue("AXRole")
                    local gcValue = gc:attributeValue("AXValue")
                    if gcRole == "AXStaticText" and gcValue then
                        attrs["grandchild" .. i .. "_" .. j .. "_text"] = gcValue
                    end
                end
            end
        end
    end

    -- Determine the best title to use
    local title = attrs.title
    if (not title or title == "") then title = attrs.desc end
    if (not title or title == "") then title = attrs.value end
    if (not title or title == "") then title = attrs.label end
    if (not title or title == "") then title = attrs.help end

    -- Check child text
    if (not title or title == "") then
        for k, v in pairs(attrs) do
            if k:match("child.*_text") and v and v ~= "" then
                title = v
                break
            end
        end
    end

    return title, attrs
end

--- Process found buttons and click safe ones
--- @param buttons table Array of button elements
--- @param appName string Application name
--- @param windowTitle string Window title
--- @param config table Configuration
local function processButtons(buttons, appName, windowTitle, config)
    local spoon = M.spoon
    local log = spoon and spoon.logger

    -- Log button details when we have few buttons (likely a permission dialog)
    local isLikelyDialog = #buttons <= 10
    if log and isLikelyDialog then
        log.i(string.format("=== DIALOG DETECTED: %d buttons in %s ===", #buttons, appName))
    end

    for i, button in ipairs(buttons) do
        local title, attrs = extractButtonText(button, log)

        -- Enhanced logging for dialogs
        if log and isLikelyDialog then
            local attrStr = ""
            for k, v in pairs(attrs) do
                if v and v ~= "" then
                    attrStr = attrStr .. string.format(" %s='%s'", k, tostring(v))
                end
            end
            if attrStr == "" then
                attrStr = " [ALL ATTRS NIL]"
            end
            log.i(string.format("  Button %d:%s", i, attrStr))
        end

        if title and title ~= "" then

            -- Merge custom allowed buttons with defaults
            local customAllowed = config.customAllowedButtons
            local mergedAllowed = nil
            if customAllowed and #customAllowed > 0 then
                mergedAllowed = {}
                for _, b in ipairs(safety.ALLOWED_BUTTONS) do
                    table.insert(mergedAllowed, b)
                end
                for _, b in ipairs(customAllowed) do
                    table.insert(mergedAllowed, b)
                end
            end

            -- Check safety
            local safe, reason = safety.isButtonSafe(
                title,
                appName,
                windowTitle,
                mergedAllowed
            )

            if safe then
                if log then log.i("  -> CLICKING: " .. title) end
                -- Click it!
                local success = button:performAction("AXPress")

                if success then
                    M.lastClickTime = hs.timer.secondsSinceEpoch() * 1000

                    -- Update stats
                    spoon.stats = configMod.incrementStats(spoon.stats, title)

                    -- Trigger UI feedback
                    ui.onButtonClicked(title, appName, reason)

                    return true
                end
            end
        else
            -- Button has no identifiable text - log all available attributes for investigation
            if log and isLikelyDialog then
                -- Try to get the button's frame/position for context
                local frame = button:attributeValue("AXFrame")
                local enabled = button:attributeValue("AXEnabled")
                local focused = button:attributeValue("AXFocused")
                log.w(string.format("  Button %d has NO TEXT - enabled=%s focused=%s frame=%s",
                    i,
                    tostring(enabled),
                    tostring(focused),
                    frame and string.format("{x=%d,y=%d,w=%d,h=%d}", frame.x, frame.y, frame.w, frame.h) or "nil"
                ))

                -- Try getting ALL attribute names to see what's available
                local allAttrNames = button:attributeNames()
                if allAttrNames then
                    log.w("    Available attributes: " .. table.concat(allAttrNames, ", "))
                end
            end
        end
    end

    return false
end

--- Search a window's UI tree for buttons and click safe ones
--- @param win userdata Hammerspoon window object
local function scanAndClickButtons(win)
    local spoon = M.spoon
    local log = spoon and spoon.logger

    if log then log.d("scanAndClickButtons called") end
    if not win then
        if log then log.d("  -> no window") end
        return
    end

    if not spoon or not spoon.enabled then
        if log then log.d("  -> spoon not enabled") end
        return
    end

    local config = spoon.config

    -- Debounce: don't click too rapidly
    local now = hs.timer.secondsSinceEpoch() * 1000
    if (now - M.lastClickTime) < (config.debounceMs or 300) then
        -- Don't spam log with debounce messages
        return
    end

    -- Verify it's a target app
    local app = win:application()
    if not app then
        if log then log.d("  -> no app") end
        return
    end

    local appName = app:name()
    if not isTargetApp(appName) then
        -- Don't log non-target apps to reduce noise
        return
    end

    -- Get accessibility element
    local axWin = hs.axuielement.windowElement(win)
    if not axWin then
        if log then log.d("  -> no axWin for " .. appName) end
        return
    end

    -- Get window title for context checking
    local windowTitle = win:title()

    -- Use the application element and search for buttons
    local axApp = hs.axuielement.applicationElement(app)
    if not axApp then
        if log then log.d("  -> no axApp for " .. appName) end
        return
    end

    if log then log.d("Searching for buttons in " .. appName) end

    -- First, let's dump the UI hierarchy to understand the structure
    local hierarchyDumped = false
    local function dumpHierarchy(element, depth, maxDumpDepth)
        if depth > maxDumpDepth then return end
        local indent = string.rep("  ", depth)
        local role = element:attributeValue("AXRole") or "?"
        local title = element:attributeValue("AXTitle") or ""
        local desc = element:attributeValue("AXDescription") or ""
        local value = element:attributeValue("AXValue") or ""
        local childCount = 0
        local children = element:attributeValue("AXChildren")
        if children then childCount = #children end

        local info = role
        if title ~= "" then info = info .. " title='" .. title .. "'" end
        if desc ~= "" then info = info .. " desc='" .. desc .. "'" end
        if value ~= "" and type(value) == "string" then info = info .. " value='" .. value:sub(1,50) .. "'" end
        info = info .. " children=" .. childCount

        if log then log.i(indent .. info) end

        if children then
            for _, child in ipairs(children) do
                dumpHierarchy(child, depth + 1, maxDumpDepth)
            end
        end
    end

    -- Recursively find all buttons in the UI tree
    local buttons = {}
    local maxDepth = 30  -- Increase depth for Electron apps
    local maxElements = 1000  -- Increase limit

    local function findButtons(element, depth)
        if depth > maxDepth or #buttons > maxElements then return end

        local role = element:attributeValue("AXRole")

        -- Look for buttons
        if role == "AXButton" then
            table.insert(buttons, element)
        end

        -- Get children and recurse
        local children = element:attributeValue("AXChildren")
        if children then
            for _, child in ipairs(children) do
                findButtons(child, depth + 1)
            end
        end
    end

    -- Start from the window element (not app, since we want the focused window)
    local ok, err = pcall(function()
        findButtons(axWin, 0)
    end)

    -- STRATEGY: Look for "Allow" button text directly rather than counting buttons.
    -- The permission dialog has a button with title "Allow once ⌘ ⏎" or similar.
    local foundAllowButton = nil
    for _, button in ipairs(buttons) do
        local title = button:attributeValue("AXTitle") or ""
        local titleLower = title:lower()
        -- Match "Allow once" or "Allow always" but not "Auto-approve..." toggle
        if titleLower:find("allow once") or titleLower:find("allow always") then
            foundAllowButton = button
            debugLog("Found Allow button: " .. title)
            break
        end
    end

    -- Debounce: don't trigger if we sent a keystroke recently (within 2 seconds)
    local now = hs.timer.secondsSinceEpoch() * 1000
    local timeSinceLastClick = now - (M.lastClickTime or 0)
    local debounceMs = 2000

    if foundAllowButton and timeSinceLastClick > debounceMs then
        local detectMsg = "=== PERMISSION DIALOG DETECTED - Found Allow button, sending Cmd+Return ==="
        if log then log.i(detectMsg) end
        debugLog(detectMsg)

        -- Make sure Claude is the frontmost app
        local app = win:application()
        if app then
            app:activate()
        end

        -- Short delay to ensure activation completes
        hs.timer.doAfter(0.1, function()
            -- Use eventtap.keyStroke which is more reliable than AppleScript for Electron apps
            hs.eventtap.keyStroke({"cmd"}, "return", 0)
            if log then log.i("=== Cmd+Return sent ===") end
            debugLog("=== Cmd+Return sent ===")
        end)

        M.lastClickTime = hs.timer.secondsSinceEpoch() * 1000

        -- Update stats
        spoon.stats = configMod.incrementStats(spoon.stats, "Cmd+Enter (dialog)")

        -- Trigger UI feedback
        ui.onButtonClicked("Cmd+Enter", appName, "Permission dialog auto-confirmed")

        return true
    end

    -- Reduce log noise - only log when something interesting happens
    -- (Allow button detection is already logged above)

    if not ok then
        if log then log.w("findButtons failed: " .. tostring(err)) end
        return
    end

    if #buttons == 0 then
        if log then log.d("No buttons found in " .. appName) end
        return
    end

    if log then log.i("Found " .. #buttons .. " buttons in " .. appName) end
    processButtons(buttons, appName, windowTitle, config)
end

--- Set up window filter to watch for target apps
function M.setupWatchers()
    local config = M.spoon and M.spoon.config or {}
    local targets = config.targetApps or {}

    debugLog("setupWatchers called, targeting: " .. table.concat(targets, ", "))

    -- Window filter for target apps
    M.windowFilter = hs.window.filter.new(targets)

    -- React to window creation
    M.windowFilter:subscribe(hs.window.filter.windowCreated, function(win)
        hs.timer.doAfter((config.uiRenderDelayMs or 100) / 1000, function()
            scanAndClickButtons(win)
        end)
    end)

    -- React to window focus
    M.windowFilter:subscribe(hs.window.filter.windowFocused, function(win)
        hs.timer.doAfter((config.uiRenderDelayMs or 100) / 1000, function()
            scanAndClickButtons(win)
        end)
    end)

    -- Backup polling (catches dialogs that don't trigger events)
    local pollInterval = config.pollIntervalSec or 0.5
    local log = M.spoon and M.spoon.logger
    if log then log.i("Setting up poll timer with interval: " .. pollInterval) end

    M.pollTimer = hs.timer.doEvery(pollInterval, function()
        if not M.spoon or not M.spoon.enabled then return end

        local focusedWin = hs.window.focusedWindow()
        if focusedWin then
            local app = focusedWin:application()
            local appName = app and app:name() or "unknown"
            -- Only log polls for target apps to reduce noise
            if isTargetApp(appName) then
                if log then log.d("Poll: checking " .. appName) end
            end
            scanAndClickButtons(focusedWin)
        end
    end)

    -- Watch for app launches to catch new terminal instances
    M.appWatcher = hs.application.watcher.new(function(appName, eventType, app)
        if eventType == hs.application.watcher.launched then
            if isTargetApp(appName) then
                -- Give app time to create windows
                hs.timer.doAfter(1, function()
                    local wins = app:allWindows()
                    for _, win in ipairs(wins) do
                        scanAndClickButtons(win)
                    end
                end)
            end
        end
    end)
    M.appWatcher:start()
end

--- Clean up all watchers
function M.cleanup()
    if M.windowFilter then
        M.windowFilter:unsubscribeAll()
        M.windowFilter = nil
    end

    if M.pollTimer then
        M.pollTimer:stop()
        M.pollTimer = nil
    end

    if M.appWatcher then
        M.appWatcher:stop()
        M.appWatcher = nil
    end
end

--- Force a scan of all target app windows (useful for manual trigger)
function M.scanAllWindows()
    local config = M.spoon and M.spoon.config or {}
    local targets = config.targetApps or {}

    for _, appName in ipairs(targets) do
        local app = hs.application.get(appName)
        if app then
            local wins = app:allWindows()
            for _, win in ipairs(wins) do
                if scanAndClickButtons(win) then
                    return true  -- Stop after first click
                end
            end
        end
    end
    return false
end

return M
