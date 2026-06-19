from __future__ import annotations

from pathlib import Path

from agent_security_scanner.config import ScannerConfig


TEXT_SUFFIXES = {
    "",
    ".bat",
    ".cmd",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".js",
    ".jsx",
    ".md",
    ".mjs",
    ".ps1",
    ".py",
    ".sh",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".yaml",
    ".yml",
}

TEXT_FILENAMES = {
    ".dockerignore",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "binding.gyp",
    "compose.yml",
    "compose.yaml",
    "devcontainer.json",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Dockerfile",
    "Makefile",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "Rakefile",
    "Justfile",
    "requirements.txt",
    "yarn.lock",
}


def iter_candidate_files(root: Path, config: ScannerConfig):
    if root.is_file():
        if is_candidate_file(root, config):
            yield root
        return

    for path in root.rglob("*"):
        if any(part in config.excluded_dirs for part in path.parts):
            continue
        if path.is_file() and is_candidate_file(path, config):
            yield path


def is_candidate_file(path: Path, config: ScannerConfig) -> bool:
    try:
        if path.stat().st_size > config.max_file_size_bytes:
            return False
    except OSError:
        return False

    return path.name in TEXT_FILENAMES or path.suffix.lower() in TEXT_SUFFIXES


def read_text_file(path: Path) -> str | None:
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    for encoding in ("utf-8", "utf-8-sig", "gb18030", "latin-1"):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None
