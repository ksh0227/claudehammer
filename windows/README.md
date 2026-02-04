# ClaudeHammer for Windows

Windows port of [ClaudeHammer](https://github.com/mattbeane/claudehammer). Auto-accepts permission prompts in Claude Code (terminal) and the Claude Desktop app (Electron).

## How it works

ClaudeHammer monitors for permission prompts and accepts them automatically.

**Claude Desktop app**: Finds "Always allow" and "Allow once" buttons via the Windows UI Automation API and clicks them directly. Prefers "Always allow" when available. Works even when the Claude window is in the background — it briefly brings Claude to the foreground, clicks, and restores your original window.

**Terminal (Claude Code)**: Detects prompts via UIA text and regex pattern matching, then sends a "y" keystroke. A blocklist prevents auto-accepting dangerous operations (delete, format, drop, etc.) using whole-word matching to avoid false positives from paths like `C:\Users\...\Dropbox\...`.

## Requirements

- Windows 10/11
- Python 3.10+
- Administrator privileges (for global hotkey registration)

## Install

```powershell
cd windows
powershell -ExecutionPolicy Bypass -File install.ps1
```

Or manually:

```powershell
pip install -r requirements.txt
```

## Usage

```powershell
python claudehammer.py
```

A system tray icon (lightning bolt) appears. Right-click for options.

| Action | How |
|---|---|
| Toggle on/off | `Ctrl+Shift+A` or tray menu |
| View audit log | Tray menu → View Audit Log |
| Edit config | Tray menu → Edit Config |
| Quit | Tray menu → Quit |

## Configuration

Stored in `~/.claudehammer/config.json` (created on first run):

```json
{
  "hotkey": "ctrl+shift+a",
  "poll_interval": 0.8,
  "accept_cooldown": 2.0,
  "accept_key": "y"
}
```

## Technical notes

**Electron window hierarchy**: The Claude Desktop app (Electron) uses a top-level frame window (`Chrome_WidgetWin_1`) that only contains title bar buttons. The web content — including permission dialogs — lives in a child window with class `Chrome_RenderWidgetHostHWND`. ClaudeHammer uses `EnumChildWindows` to find this content window.

**pywinauto quirks**: The `descendants()` method returns a lazy iterator that can crash with `AttributeError` when elements have `None` parents. ClaudeHammer materializes the iterator into a list to avoid this.

**Button names**: UIA button names in the Electron app include keyboard shortcut text, e.g. `"Always allow for project (local) Ctrl Enter"` rather than just `"Always allow for project (local)"`. Matching uses `startswith()` to handle this.

## Audit log

All actions are logged to `~/.claudehammer/audit.log`:

```
2026-02-04 10:23:15  INFO     ACCEPTED (click)  Always allow for session Ctrl Enter
2026-02-04 10:24:01  WARNING  BLOCKED   ...delete all files...
```
