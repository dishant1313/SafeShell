"""SafeShell CLI entry point.

Provides the Typer-based command-line interface. Full TUI is implemented in Phase 10.
"""

import typer

from safeshell import __version__

app = typer.Typer(
    name="safeshell",
    help="SafeShell — verified transactional command execution framework.",
    invoke_without_command=True,
)


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    show_version: bool = typer.Option(False, "--version", "-V", help="Show version."),
) -> None:
    """SafeShell — verified transactional command execution framework."""
    if show_version or (ctx.invoked_subcommand is None):
        typer.echo(f"safeshell {__version__} — Phase 1 skeleton")
        raise typer.Exit()


@app.command()
def version() -> None:
    """Print SafeShell version and build phase."""
    typer.echo(f"safeshell {__version__} — Phase 1 skeleton")


if __name__ == "__main__":
    app()
