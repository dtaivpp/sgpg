"""Entry point for ``python -m sgpg`` and the installed ``sgpg`` script."""

from __future__ import annotations

from sgpg.cli import app


def main() -> None:
    app()


if __name__ == "__main__":
    main()
