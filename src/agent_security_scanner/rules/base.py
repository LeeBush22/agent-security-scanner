from __future__ import annotations

from abc import ABC, abstractmethod

from agent_security_scanner.models import FileContext, Finding


class Rule(ABC):
    @abstractmethod
    def scan(self, context: FileContext) -> list[Finding]:
        """Scan a single file and return findings."""
