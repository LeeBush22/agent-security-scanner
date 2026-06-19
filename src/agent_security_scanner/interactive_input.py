from __future__ import annotations

from dataclasses import dataclass
import sys
from typing import Callable
from typing import Optional

import typer

from agent_security_scanner.i18n import Language


class BackRequested(Exception):
    """Raised when the user asks to return to the previous menu."""


BACK_WORDS = {"back", "b", "q", "quit", "exit", "esc", "\x1b"}


@dataclass(frozen=True)
class PromptSession:
    language: Language

    def ask(self, message: str, default: str | None = None) -> str:
        value = _prompt_text(message, default=default, language=self.language).strip()
        if _is_back_request(value):
            raise BackRequested
        return value

    def confirm(self, message: str, default: bool = False) -> bool:
        value = _prompt_text(message, default="y" if default else "n", language=self.language).strip().lower()
        if _is_back_request(value):
            raise BackRequested
        if value in {"y", "yes", "true", "1", "是", "确认"}:
            return True
        if value in {"n", "no", "false", "0", "否", "不"}:
            return False
        return default


def _prompt_text(message: str, default: Optional[str], language: Language) -> str:
    try:
        if _should_read_keys():
            value = _prompt_text_with_keys(message, default)
        else:
            value = typer.prompt(message, default=default) if default is not None else typer.prompt(message)
    except (EOFError, KeyboardInterrupt):
        raise BackRequested
    return "" if value is None else str(value)


def _is_back_request(value: str) -> bool:
    return value.strip().lower() in BACK_WORDS


def _should_read_keys() -> bool:
    return bool(getattr(sys.stdin, "isatty", lambda: False)() and getattr(sys.stdout, "isatty", lambda: False)())


def _prompt_text_with_keys(message: str, default: Optional[str]) -> str:
    _write_stdout(_format_prompt(message, default))
    value = _read_terminal_line()
    if value == "" and default is not None:
        return default
    return value


def _format_prompt(message: str, default: Optional[str]) -> str:
    if default is None:
        return f"{message}: "
    return f"{message} [{default}]: "


def _read_terminal_line() -> str:
    if sys.platform == "win32":
        return _read_windows_line()
    return _read_posix_line()


def _read_windows_line() -> str:
    try:
        import msvcrt
    except ImportError:
        return sys.stdin.readline().rstrip("\r\n")

    def read_key() -> str:
        char = msvcrt.getwch()
        if char in {"\x00", "\xe0"}:
            msvcrt.getwch()
            return ""
        return char

    return _read_key_line(read_key, _write_stdout)


def _read_posix_line() -> str:
    try:
        import termios
        import tty
    except ImportError:
        return sys.stdin.readline().rstrip("\r\n")

    fd = sys.stdin.fileno()
    original_settings = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        return _read_key_line(lambda: sys.stdin.read(1), _write_stdout)
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, original_settings)


def _read_key_line(read_key: Callable[[], str], write_text: Callable[[str], None]) -> str:
    chars: list[str] = []
    while True:
        char = read_key()
        if char == "":
            continue
        if char == "\x1b":
            write_text("\n")
            raise BackRequested
        if char in {"\r", "\n"}:
            write_text("\n")
            return "".join(chars)
        if char in {"\x03", "\x04"}:
            raise KeyboardInterrupt
        if char in {"\b", "\x7f"}:
            if chars:
                chars.pop()
                write_text("\b \b")
            continue
        if char >= " ":
            chars.append(char)
            write_text(char)


def _write_stdout(text: str) -> None:
    sys.stdout.write(text)
    sys.stdout.flush()
