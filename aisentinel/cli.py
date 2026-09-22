import typer

from aisentinel.scanners.artifact import scan_artifacts
from aisentinel.scanners.dependency import scan_dependencies

app = typer.Typer(
    name="aisentinel",
    help="Policy-driven ingestion gate for AI models.",
    no_args_is_help=True,
    add_completion=False,
)


@app.callback()
def _main():
    """Policy-driven ingestion gate for AI models."""


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
    """Scan a model's artifacts and dependencies, then print an ingestion report."""
    typer.echo("AI-SENTINEL — Model Ingestion Report")
    typer.echo(f"Model:    {model}")

    try:
        artifact_report = scan_artifacts(model)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[ERROR] Could not scan model artifacts: {exc}")
        raise typer.Exit(code=2)

    typer.echo(f"Revision: {artifact_report.revision}")
    typer.echo(f"Files:    {len(artifact_report.files)}")
    typer.echo("")

    typer.echo("Artifacts")
    for f in artifact_report.findings:
        tag = _TAG.get(f.severity, "[????]")
        typer.echo(f"  {tag} {f.check}: {f.message}")

    typer.echo("")
    typer.echo("Dependencies")
    try:
        dep_report = scan_dependencies(model)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"  [ERROR] Could not read dependencies: {exc}")
        raise typer.Exit(code=2)

    if dep_report.dependencies:
        typer.echo(f"  Source: {dep_report.source_file}")
        for d in dep_report.dependencies:
            pin = f"=={d.version}" if d.version else " (unpinned)"
            typer.echo(f"  - {d.name}{pin}")
    else:
        typer.echo(f"  [INFO] {dep_report.note}")


if __name__ == "__main__":
    app()