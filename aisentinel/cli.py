import typer

from aisentinel.scanners.artifact import scan_artifacts

app = typer.Typer(
    name="aisentinel",
    help="Policy-driven ingestion gate for AI models.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _main():
    """Policy-driven ingestion gate for AI models."""


# Map severity to a short tag shown in the report.
_TAG = {
    "INFO": "[INFO]",
    "LOW": "[LOW ]",
    "MEDIUM": "[WARN]",
    "HIGH": "[FAIL]",
    "CRITICAL": "[FAIL]",
}


@app.command()
def scan(
    model: str = typer.Argument(..., help="Hugging Face model id, e.g. 'org/model'."),
):
    """Scan a model's artifacts and print an ingestion report."""
    typer.echo("AI-SENTINEL — Model Ingestion Report")
    typer.echo(f"Model:    {model}")

    try:
        report = scan_artifacts(model)
    except Exception as exc:  # noqa: BLE001 - surface any Hub error cleanly
        typer.echo(f"[ERROR] Could not scan model: {exc}")
        raise typer.Exit(code=2)

    typer.echo(f"Revision: {report.revision}")
    typer.echo(f"Files:    {len(report.files)}")
    typer.echo("")

    for f in report.findings:
        tag = _TAG.get(f.severity, "[????]")
        typer.echo(f"{tag} {f.check}: {f.message}")


if __name__ == "__main__":
    app()