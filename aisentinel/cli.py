import typer

app = typer.Typer(
    name="aisentinel",
    help="Policy-driven ingestion gate for AI models.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _main():
    """Policy-driven ingestion gate for AI models."""

@app.command()
def scan(
    model: str = typer.Argument(..., help="Hugging Face model id, e.g. 'org/model'."),
):
    """Scan a model and print an ingestion report. (stub)"""
    typer.echo(f"AI-SENTINEL — scanning: {model}")
    typer.echo("[stub] No checks implemented yet. Phase 1 will add artifact scanning.")


if __name__ == "__main__":
    app()