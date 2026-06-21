from __future__ import annotations

import nox


nox.options.sessions = ["tests", "typecheck"]


@nox.session(python=["3.10", "3.11", "3.12"])
def tests(session: nox.Session) -> None:
    session.install(".[dev]")
    session.run("coverage", "run", "-m", "pytest", "-q")
    session.run("coverage", "report")


@nox.session(python="3.11")
def typecheck(session: nox.Session) -> None:
    session.install(".[dev]")
    session.run("mypy")
