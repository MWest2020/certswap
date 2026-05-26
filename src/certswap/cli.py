from __future__ import annotations

import typer

from certswap import __version__
from certswap.commands.apply import apply_app
from certswap.commands.inspect import inspect_command
from certswap.commands.plan import plan_app
from certswap.commands.upcoming import upcoming_command
from certswap.commands.verify import verify_app

app = typer.Typer(
    name="certswap",
    help="Deterministic TLS bundle swap CLI.",
    no_args_is_help=True,
    invoke_without_command=True,
    add_completion=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def _root(
    version: bool = typer.Option(
        False,
        "--version",
        help="Print version and exit.",
        is_eager=True,
        callback=_version_callback,
    ),
) -> None:
    """Deterministic TLS bundle swap CLI."""


app.command(name="inspect")(inspect_command)
app.command(name="upcoming")(upcoming_command)
app.add_typer(plan_app, name="plan")
app.add_typer(apply_app, name="apply")
app.add_typer(verify_app, name="verify")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
