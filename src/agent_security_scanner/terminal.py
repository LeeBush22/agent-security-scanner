from __future__ import annotations

import os
import shutil
import sys
from ctypes import POINTER, Structure, byref, c_short, c_uint32

from rich.console import Console


MIN_TERMINAL_WIDTH = 60
MAX_REASONABLE_TERMINAL_WIDTH = 400
STD_OUTPUT_HANDLE = c_uint32(-11).value


def visible_terminal_width() -> int:
    """Return the current visible terminal width, not the scrollback buffer width."""
    for width in _candidate_widths():
        if _valid_width(width):
            assert width is not None
            return max(MIN_TERMINAL_WIDTH, width)
    width = 80
    return max(MIN_TERMINAL_WIDTH, width)


def sync_console_width(console: Console) -> int:
    width = visible_terminal_width()
    console._width = width
    return width


def responsive_console(console: Console | None = None) -> Console:
    console = console or Console()
    sync_console_width(console)
    return console


def _candidate_widths() -> list[int | None]:
    widths: list[int | None] = [
        _env_width(),
        _windows_visible_width(),
        _os_terminal_width(sys.__stdout__),
        _os_terminal_width(sys.stdout),
        _os_terminal_width(sys.__stderr__),
        _os_terminal_width(sys.stderr),
        _shutil_width(),
    ]
    return widths


def _valid_width(width: int | None) -> bool:
    return width is not None and MIN_TERMINAL_WIDTH <= width <= MAX_REASONABLE_TERMINAL_WIDTH


def _env_width() -> int | None:
    value = os.environ.get("AGENT_SCAN_TERMINAL_WIDTH")
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _windows_visible_width() -> int | None:
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.argtypes = [wintypes.DWORD]
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetConsoleScreenBufferInfo.argtypes = [
            wintypes.HANDLE,
            POINTER(_ConsoleScreenBufferInfo),
        ]
        kernel32.GetConsoleScreenBufferInfo.restype = wintypes.BOOL

        handle = kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        if handle in (None, 0, ctypes.c_void_p(-1).value):
            return None
        info = _ConsoleScreenBufferInfo()
        if not kernel32.GetConsoleScreenBufferInfo(handle, byref(info)):
            return None
        return int(info.sr_window.right - info.sr_window.left + 1)
    except Exception:
        return None


def _os_terminal_width(stream: object) -> int | None:
    try:
        fileno = stream.fileno()  # type: ignore[attr-defined]
        return os.get_terminal_size(fileno).columns
    except (AttributeError, OSError, ValueError):
        return None


def _shutil_width() -> int | None:
    try:
        return shutil.get_terminal_size(fallback=(80, 24)).columns
    except Exception:
        return None


class _SmallRect(Structure):
    _fields_ = [
        ("left", c_short),
        ("top", c_short),
        ("right", c_short),
        ("bottom", c_short),
    ]


class _CoordStruct(Structure):
    _fields_ = [
        ("x", c_short),
        ("y", c_short),
    ]


class _ConsoleScreenBufferInfo(Structure):
    _fields_ = [
        ("dw_size", _CoordStruct),
        ("dw_cursor_position", _CoordStruct),
        ("w_attributes", c_short),
        ("sr_window", _SmallRect),
        ("dw_maximum_window_size", _CoordStruct),
    ]
