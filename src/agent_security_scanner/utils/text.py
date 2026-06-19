from __future__ import annotations


def mask_secret(value: str, keep_start: int = 6, keep_end: int = 4) -> str:
    compact = value.strip()
    if len(compact) <= keep_start + keep_end + 3:
        return compact[:2] + "..." if len(compact) > 2 else "..."
    return f"{compact[:keep_start]}...{compact[-keep_end:]}"


def line_col_from_offset(text: str, offset: int) -> tuple[int, int]:
    before = text[:offset]
    line = before.count("\n") + 1
    last_newline = before.rfind("\n")
    column = offset + 1 if last_newline == -1 else offset - last_newline
    return line, column


def line_at(text: str, line_number: int) -> str:
    lines = text.splitlines()
    if line_number < 1 or line_number > len(lines):
        return ""
    return lines[line_number - 1].strip()
