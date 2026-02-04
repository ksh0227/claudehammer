#!/usr/bin/env python3
"""
ClaudeHammer for Windows
========================
Auto-accept permission prompts in Claude Code (terminal) and Claude
Desktop (Electron) on Windows.

Port of https://github.com/mattbeane/claudehammer (macOS).
Author: Sukhun Kang

Two acceptance modes:

  Terminal (Claude Code in PowerShell, cmd, etc.)
    Detects prompts via UIA text + regex, sends a keystroke ("y").
    Blocklist prevents auto-accepting dangerous actions.

  Desktop (Claude.exe Electron app)
    Finds "Allow once" / "Always allow" buttons via UIA, clicks them.
    Prefers "Always allow" when available.
    Works even when the Claude window is in the background.

Usage:
    pip install -r requirements.txt
    python claudehammer.py

Toggle with Ctrl+Shift+A (configurable in ~/.claudehammer/config.json).
"""

import ctypes
import ctypes.wintypes as wt
import json
import logging
import os
import re
import sys
import threading
import time
from pathlib import Path

# ── Platform check ───────────────────────────────────────────────────────────

if sys.platform != "win32":
    sys.exit("ClaudeHammer for Windows requires Windows.")

# ── Dependency loading ───────────────────────────────────────────────────────

def _require(module, pip_name=None):
    """Import or exit with install instructions."""
    try:
        return __import__(module)
    except ImportError:
        sys.exit(f"Missing dependency: pip install {pip_name or module}")

_require("keyboard")
_require("psutil")
_require("pystray")
_require("PIL", "Pillow")

import keyboard
import psutil
import pystray
from PIL import Image, ImageDraw

# pywinauto is optional but strongly recommended; enables UIA text
# detection for terminals and button detection for the desktop app.
try:
    from pywinauto import Desktop as UIADesktop
    HAS_UIA = True
except ImportError:
    HAS_UIA = False

# ── Configuration ────────────────────────────────────────────────────────────

DATA_DIR = Path.home() / ".claudehammer"
LOG_FILE = DATA_DIR / "audit.log"
CONFIG_FILE = DATA_DIR / "config.json"

DEFAULTS = {
    "hotkey": "ctrl+shift+a",
    "poll_interval": 0.8,
    "accept_cooldown": 2.0,
    "accept_key": "y",
}

# Words that must NEVER be auto-accepted (terminal blocklist).
# Uses whole-word matching to avoid false positives (e.g. "Dropbox").
BLOCKLIST = frozenset([
    "delete", "remove", "purchase", "send", "unsubscribe",
    "subscribe", "share", "destroy", "drop", "truncate",
    "format", "wipe", "purge",
])

# Terminal process names to monitor for Claude Code prompts.
TERMINALS = frozenset([
    "windowsterminal.exe", "powershell.exe", "pwsh.exe", "cmd.exe",
    "code.exe", "alacritty.exe", "wezterm-gui.exe", "warp.exe",
    "hyper.exe", "kitty.exe", "mintty.exe", "conhost.exe",
    "ghostty.exe",
])

# Claude Desktop (Electron) process name.
CLAUDE_DESKTOP = frozenset(["claude.exe"])

# Regex patterns that signal a Claude Code permission prompt (terminal).
PROMPT_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"allow\s+(this|claude|tool|command|action)",
        r"do you want to\s+(allow|proceed|continue)",
        r"\[y[/|]n\]",
        r"approve\s+(this|tool|action)",
        r"wants to\s+(run|execute|read|write|edit|create|access)",
        r"permission\s+(required|needed|request)",
        r"allow\s+once",
        r"always\s+allow",
    ]
]

# ── Win32 helpers ────────────────────────────────────────────────────────────

_user32 = ctypes.windll.user32
_WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)


def _foreground_hwnd() -> int:
    """Return the HWND of the current foreground window."""
    return _user32.GetForegroundWindow()


def _bring_to_foreground(hwnd: int):
    """Reliably bring a window to the foreground.

    Windows blocks SetForegroundWindow unless the caller's input queue
    is attached to the foreground thread. We attach, switch, detach.
    """
    fg = _user32.GetForegroundWindow()
    current = _user32.GetWindowThreadProcessId(fg, None)
    target = _user32.GetWindowThreadProcessId(hwnd, None)
    if current != target:
        _user32.AttachThreadInput(current, target, True)
    _user32.SetForegroundWindow(hwnd)
    if current != target:
        _user32.AttachThreadInput(current, target, False)


def _window_class(hwnd: int) -> str:
    """Return the window class name."""
    buf = ctypes.create_unicode_buffer(256)
    _user32.GetClassNameW(hwnd, buf, 256)
    return buf.value


def _window_title(hwnd: int) -> str:
    """Return the window title text."""
    length = _user32.GetWindowTextLengthW(hwnd) + 1
    buf = ctypes.create_unicode_buffer(length)
    _user32.GetWindowTextW(hwnd, buf, length)
    return buf.value


def _window_pid(hwnd: int) -> int:
    """Return the PID that owns the window."""
    pid = wt.DWORD()
    _user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def _proc_name(pid: int) -> str:
    """Return the lowercase process name for a PID."""
    try:
        return psutil.Process(pid).name().lower()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def _find_claude_content_hwnds() -> list:
    """Return HWNDs of Claude Desktop Electron content windows.

    Electron uses a top-level frame window (Chrome_WidgetWin_1) that
    only contains the title bar buttons (Minimize, Maximize, Close).
    The actual web content — including permission dialog buttons —
    lives in a child window with class Chrome_RenderWidgetHostHWND.

    EnumWindows returns only the frame. We must also call
    EnumChildWindows to find the content child, which is the HWND
    that pywinauto can query for Allow/Deny buttons.
    """
    top_level = []

    @_WNDENUMPROC
    def _cb(hwnd, _lparam):
        try:
            if not _user32.IsWindowVisible(hwnd):
                return True
            if _proc_name(_window_pid(hwnd)) in CLAUDE_DESKTOP:
                top_level.append(hwnd)
        except Exception:
            pass
        return True

    _user32.EnumWindows(_cb, 0)

    results = []
    for parent in top_level:
        children = []

        @_WNDENUMPROC
        def _child_cb(hwnd, _lparam):
            children.append(hwnd)
            return True

        _user32.EnumChildWindows(parent, _child_cb, 0)

        content_found = False
        for child in children:
            if "Chrome_RenderWidgetHostHWND" in _window_class(child):
                results.append(child)
                content_found = True
                break

        if not content_found:
            results.append(parent)

    return results


# ── Core application ─────────────────────────────────────────────────────────

class ClaudeHammer:

    def __init__(self):
        self.enabled = True
        self.running = True
        self.accepted = 0
        self.blocked = 0
        self.last_accept_time = 0.0
        self.tray_icon = None

        self.cfg = dict(DEFAULTS)
        self._load_config()
        self._init_logging()

    # ── Config & logging ─────────────────────────────────────────────────

    def _load_config(self):
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    user = json.load(f)
                self.cfg.update(user)
            except (json.JSONDecodeError, OSError):
                pass

    def _save_default_config(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if not CONFIG_FILE.exists():
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(DEFAULTS, f, indent=2)

    def _init_logging(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        self.log = logging.getLogger("claudehammer")
        self.log.setLevel(logging.INFO)
        if not self.log.handlers:
            fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
            fh.setFormatter(logging.Formatter(
                "%(asctime)s  %(levelname)-7s  %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            ))
            self.log.addHandler(fh)
        self.log.info("Session started (UIA=%s)", HAS_UIA)

    # ── Detection ────────────────────────────────────────────────────────

    def _is_claude_terminal(self, hwnd: int) -> bool:
        """Return True if the window is a terminal likely running Claude Code."""
        proc = _proc_name(_window_pid(hwnd))
        if proc not in TERMINALS:
            return False
        title = _window_title(hwnd).lower()
        if "claude" in title:
            return True
        return self._has_claude_child(_window_pid(hwnd))

    def _has_claude_child(self, pid: int) -> bool:
        """Walk the process tree looking for a Claude Code child process."""
        try:
            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                try:
                    cmdline = " ".join(child.cmdline()).lower()
                    if "claude" in cmdline or "@anthropic" in cmdline:
                        return True
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
        return False

    def _read_uia_text(self, hwnd: int) -> str:
        """Read accessible text elements from a window via UIA."""
        if not HAS_UIA:
            return ""
        try:
            desktop = UIADesktop(backend="uia")
            win = desktop.window(handle=hwnd)
            try:
                elems = list(win.descendants())
            except Exception:
                return ""
            parts = []
            for elem in elems:
                try:
                    name = elem.element_info.name
                    if name and len(name.strip()) > 1:
                        parts.append(name.strip())
                except Exception:
                    pass
            return "\n".join(parts[-60:])
        except Exception:
            return ""

    def _find_allow_button(self, hwnd: int):
        """Scan the UIA tree for an Allow button in a Claude Desktop window.

        Prefers "Always allow" over "Allow once". Button names in the
        Electron app include keyboard shortcut text, e.g.:
            "Always allow for project (local) Ctrl Enter"
            "Allow once Enter"

        Returns (button_element, button_name) or (None, "").
        """
        if not HAS_UIA:
            return None, ""
        try:
            desktop = UIADesktop(backend="uia")
            win = desktop.window(handle=hwnd)

            # Materialize into a list; the lazy iterator can crash on
            # elements with None parents (known pywinauto bug).
            try:
                elems = list(win.descendants())
            except Exception:
                return None, ""

            allow_once = None
            always_allow = None

            for elem in elems:
                try:
                    name = (elem.element_info.name or "").strip()
                    if not name:
                        continue
                    ctrl = (elem.element_info.control_type or "").lower()
                    if ctrl != "button":
                        continue

                    name_lower = name.lower()
                    if (name_lower.startswith("always allow")
                            or name_lower.startswith("allow for")):
                        always_allow = (elem, name)
                    elif name_lower.startswith("allow once"):
                        allow_once = (elem, name)
                except Exception:
                    pass

            if always_allow:
                return always_allow
            if allow_once:
                return allow_once
            return None, ""

        except Exception:
            return None, ""

    def _has_prompt(self, text: str) -> bool:
        """Return True if the text matches a terminal permission prompt."""
        return any(p.search(text) for p in PROMPT_PATTERNS)

    def _is_blocked(self, text: str) -> bool:
        """Return True if blocklisted words appear (whole-word match).

        Whole-word matching avoids false positives from substrings
        such as "drop" inside "Dropbox" in file paths.
        """
        lower = text.lower()
        return any(re.search(r'\b' + w + r'\b', lower) for w in BLOCKLIST)

    # ── Actions ──────────────────────────────────────────────────────────

    def _accept_keystroke(self, context: str = ""):
        """Accept a terminal prompt by sending a keystroke."""
        now = time.monotonic()
        if now - self.last_accept_time < self.cfg["accept_cooldown"]:
            return
        keyboard.send(self.cfg["accept_key"])
        self.last_accept_time = now
        self.accepted += 1
        self.log.info("ACCEPTED (key)  %s", context[:150])
        self._refresh_tray()

    def _accept_click(self, button, context: str = ""):
        """Accept a desktop prompt by invoking a UIA button."""
        now = time.monotonic()
        if now - self.last_accept_time < self.cfg["accept_cooldown"]:
            return
        try:
            button.invoke()
        except Exception:
            try:
                button.click_input()
            except Exception as exc:
                self.log.error("Click failed: %s", exc)
                return
        self.last_accept_time = now
        self.accepted += 1
        self.log.info("ACCEPTED (click)  %s", context[:150])
        self._refresh_tray()

    def _block(self, context: str = ""):
        """Record a blocked prompt."""
        self.blocked += 1
        self.log.warning("BLOCKED   %s", context[:150])
        self._refresh_tray()

    # ── Monitor loop ─────────────────────────────────────────────────────

    def _tick(self):
        """Single poll cycle: check desktop windows, then terminal."""

        # Desktop app: scan all Claude content windows (background OK).
        # The permission dialog IS the safety gate, so no blocklist
        # check is needed here.
        for hwnd in _find_claude_content_hwnds():
            try:
                btn, name = self._find_allow_button(hwnd)
            except Exception:
                continue
            if btn:
                # Bring Claude to foreground, click, restore original.
                original = _foreground_hwnd()
                if original != hwnd:
                    _bring_to_foreground(hwnd)
                    time.sleep(0.15)
                self._accept_click(btn, name)
                if original and original != hwnd:
                    time.sleep(0.15)
                    _bring_to_foreground(original)
                return

        # Terminal: only check the foreground window.
        hwnd = _foreground_hwnd()
        if not hwnd:
            return
        if not self._is_claude_terminal(hwnd):
            return
        uia_text = self._read_uia_text(hwnd)
        title = _window_title(hwnd)
        combined = f"{title}\n{uia_text}"
        if not self._has_prompt(combined):
            return
        if self._is_blocked(combined):
            self._block(combined)
            return
        self._accept_keystroke(combined)

    def _monitor(self):
        """Background thread: poll for prompts on an interval."""
        while self.running:
            if self.enabled:
                try:
                    self._tick()
                except Exception as exc:
                    self.log.error("Monitor error: %s", exc)
            time.sleep(self.cfg["poll_interval"])

    # ── Toggle ───────────────────────────────────────────────────────────

    def toggle(self):
        self.enabled = not self.enabled
        state = "ENABLED" if self.enabled else "PAUSED"
        self.log.info("Toggled: %s", state)
        self._refresh_tray()

    # ── System tray ──────────────────────────────────────────────────────

    def _make_icon(self) -> Image.Image:
        """Draw tray icon: lightning bolt (active) or pause bars (paused)."""
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        if self.enabled:
            d.rounded_rectangle([0, 0, 63, 63], radius=8, fill=(35, 35, 35))
            d.polygon(
                [(32, 2), (12, 33), (26, 33), (21, 62), (52, 27), (36, 27), (42, 2)],
                fill=(255, 210, 40),
            )
        else:
            d.rounded_rectangle([0, 0, 63, 63], radius=8, fill=(60, 60, 60))
            d.rectangle([18, 14, 28, 50], fill=(150, 150, 150))
            d.rectangle([36, 14, 46, 50], fill=(150, 150, 150))
        return img

    def _refresh_tray(self):
        if not self.tray_icon:
            return
        self.tray_icon.icon = self._make_icon()
        state = "Active" if self.enabled else "Paused"
        self.tray_icon.title = (
            f"ClaudeHammer \u2013 {state}  "
            f"(\u2713{self.accepted}  \u2717{self.blocked})"
        )

    def _open_log(self):
        os.startfile(str(LOG_FILE))

    def _open_config(self):
        self._save_default_config()
        os.startfile(str(CONFIG_FILE))

    def _quit(self):
        self.running = False
        self.log.info("Session ended")
        if self.tray_icon:
            self.tray_icon.stop()

    def _build_tray(self):
        menu = pystray.Menu(
            pystray.MenuItem(
                lambda _: "\u23f8  Pause" if self.enabled else "\u26a1  Resume",
                lambda: self.toggle(),
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("View Audit Log", lambda: self._open_log()),
            pystray.MenuItem("Edit Config", lambda: self._open_config()),
            pystray.MenuItem(
                lambda _: f"Accepted: {self.accepted}  |  Blocked: {self.blocked}",
                None,
                enabled=False,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", lambda: self._quit()),
        )
        self.tray_icon = pystray.Icon(
            "claudehammer",
            self._make_icon(),
            "ClaudeHammer \u2013 Active",
            menu,
        )

    # ── Entry point ──────────────────────────────────────────────────────

    def run(self):
        hotkey = self.cfg["hotkey"]
        keyboard.add_hotkey(hotkey, self.toggle)

        monitor_thread = threading.Thread(target=self._monitor, daemon=True)
        monitor_thread.start()

        print("ClaudeHammer for Windows")
        print(f"  Toggle:   {hotkey}")
        print(f"  Log:      {LOG_FILE}")
        if not HAS_UIA:
            print("  Warning:  pywinauto not installed; UIA detection disabled.")
            print("            pip install pywinauto")
        print()

        self._build_tray()
        self.tray_icon.run()


# ── Main ─────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    ClaudeHammer().run()
