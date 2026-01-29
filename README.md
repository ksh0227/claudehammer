# ClaudeHammer ⚡🔨

**For knowledge workers who use Claude Code but don't want to babysit it.**

You're a researcher, analyst, writer, or other knowledge worker who uses Claude Code to get real work done. But every few minutes, Claude asks for permission to read a file, run a command, or create something—and you have to stop what you're doing to click "Yes."

You're not a developer. You don't want to mess with config files or learn about `--dangerously-skip-permissions`. You just want Claude to do its job while you do yours.

**ClaudeHammer automatically clicks "Allow" and "Yes" so you can stay focused on your actual work.**

## Why This Exists

Claude Code is incredible for knowledge work—research, writing, data analysis, document processing. But its permission system assumes you're a developer who wants to approve every file read and command execution.

For knowledge workers doing agentic tasks (let Claude research this, summarize that, organize these files), stopping every 30 seconds to click "Allow" is:
- **Expensive** - your time costs money
- **Flow-breaking** - context switching kills productivity
- **Pointless** - you were going to click Yes anyway

ClaudeHammer runs quietly in your menubar and confirms those prompts for you (using Cmd+Return, the same keyboard shortcut you'd use manually).

## Safety First

ClaudeHammer is paranoid about safety. It will auto-click routine permissions but **never** dangerous actions:

| ✅ Auto-clicks | ❌ Never clicks |
|---------------|-----------------|
| Yes | Delete |
| Allow | Remove |
| Confirm | Purchase |
| OK | Send |
| Proceed | Unsubscribe |
| Continue | Subscribe |
| Accept | Share |

- **Full audit log** of every click at `~/.hammerspoon/claude-auto-allow.log`
- **One-click pause** from menubar whenever you want manual control
- **Hardcoded blocklist** prevents dangerous clicks even if misconfigured
- **Open source** - have a developer friend inspect it if you're cautious

## Quick Install

You'll need Homebrew (the Mac package manager). If you don't have it:
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

Then install ClaudeHammer:
```bash
brew install --cask hammerspoon
curl -sL https://raw.githubusercontent.com/mattbeane/claudehammer/main/install.sh | bash
```

## After Install

1. **Grant Accessibility permissions** when prompted
   - System Settings → Privacy & Security → Accessibility → Enable Hammerspoon
   - (This is how ClaudeHammer clicks buttons for you)
2. Look for **⚡** in your menubar - that means it's active
3. Start using Claude Code - permissions will auto-approve!

## Using ClaudeHammer

Once installed, just forget about it. ClaudeHammer runs quietly and clicks permission prompts automatically.

**Menubar icon meanings:**
- ⚡ = Active (auto-clicking)
- ⏸ = Paused (you're clicking manually)

**Click the icon to:**
- Pause/resume auto-clicking
- See what it's clicked recently
- View the full audit log
- Adjust settings

**Keyboard shortcut:** Press `Cmd+Shift+A` to toggle on/off

## Supported Apps

ClaudeHammer works with the Claude desktop app and terminal emulators:
- **Claude desktop app** ✓ (recommended)
- Terminal.app ✓
- iTerm2 ✓
- Warp ✓
- Kitty ✓
- Alacritty ✓
- Ghostty ✓
- WezTerm ✓
- Hyper ✓

## FAQ

**Q: Is this safe?**
A: Yes. The hardcoded blocklist prevents clicking anything destructive (Delete, Purchase, Send, etc.) even if you misconfigure it. Every click is logged so you can review what happened.

**Q: What if I want to say "No" to something?**
A: Click the ⚡ icon and select "Disable" to pause auto-clicking. Or press `Cmd+Shift+A`. Then you're back to manual approval.

**Q: I'm not technical. Will this break my computer?**
A: No. ClaudeHammer only interacts with permission dialogs in Claude (desktop or terminal). It can't affect anything else on your system.

**Q: How do I know what it clicked?**
A: Click the menubar icon → "View Audit Log" to see every action with timestamps.

**Q: What if Claude asks for something dangerous?**
A: ClaudeHammer won't click it. Buttons containing words like "Delete", "Purchase", "Send", or "Remove" are permanently blocked. You'll need to click those manually (which is the point—those deserve your attention).

## Troubleshooting

### "Hammerspoon needs Accessibility permissions"

1. Open System Settings
2. Go to Privacy & Security → Accessibility
3. Click the + button
4. Find and add Hammerspoon from your Applications folder
5. Make sure the checkbox next to it is enabled
6. Click the Hammerspoon menubar icon → Reload Config

### Not auto-clicking

1. Make sure you see ⚡ in your menubar (not ⏸)
2. Click the menubar icon → check that it says "✓ Enabled"
3. If problems persist, click the Hammerspoon icon → Console to see error messages

## Windows?

ClaudeHammer is macOS-only. Hammerspoon doesn't exist on Windows, and the accessibility APIs are completely different.

If you're a Windows developer who wants to build a port, the likely approaches are:
- **AutoHotkey** - most similar UX, can detect windows and click buttons
- **PowerShell + UI Automation** - Windows has built-in UI Automation APIs
- **Python + pywinauto** - cross-platform library for GUI automation

PRs welcome. The core logic (allowlist, blocklist, audit logging) could be shared; it's the OS integration that needs rebuilding.

## Uninstall

```bash
# Remove the spoon
rm -rf ~/.hammerspoon/Spoons/ClaudeAutoAllow.spoon

# Remove from config (edit this file and delete the ClaudeHammer lines)
open ~/.hammerspoon/init.lua

# Optionally remove Hammerspoon entirely
brew uninstall --cask hammerspoon
```

## License

MIT - Use at your own risk, but it's probably fine.

## Credits

Built by [Matt Beane](https://github.com/mattbeane) (a researcher, not a developer) with Claude.

Inspired by the realization that clicking "Yes" 50 times per hour is not a good use of anyone's time.
