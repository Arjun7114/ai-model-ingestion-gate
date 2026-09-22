import typer

from aisentinel.scanners.source import resolve_source
from aisentinel.scanners.artifact import scan_artifacts
from aisentinel.scanners.dependency import scan_dependencies
from aisentinel.intel.osv import query_osv
from aisentinel.sbom.cyclonedx import build_mlbom, write_mlbom

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
    model: str = typer.Argument(
        ..., help="Hugging Face model id (e.g. 'org/model') or a local folder path."
    ),
    sbom: str = typer.Option(
        None, "--sbom", help="Write a CycloneDX ML-BOM to this path (e.g. out.cdx.json)."
    ),
):
    """Scan a model's artifacts, dependencies and known vulnerabilities."""
    typer.echo("AI-SENTINEL — Model Ingestion Report")
    typer.echo(f"Target:   {model}")

    try:
        source = resolve_source(model)
    except Exception as exc:  # noqa: BLE001
        typer.echo(f"[ERROR] Could not resolve target: {exc}")
        raise typer.Exit(code=2)

    typer.echo(f"Kind:     {source.kind}")
    typer.echo(f"Revision: {source.revision}")
    typer.echo(f"Files:    {len(source.files)}")
    typer.echo("")

    typer.echo("Artifacts")
    for f in scan_artifacts(source).findings:
        typer.echo(f"  {_TAG.get(f.severity, '[????]')} {f.check}: {f.message}")

    typer.echo("")
    typer.echo("Dependencies")
    dep_report = scan_dependencies(source)
    if dep_report.dependencies:
        typer.echo(f"  Source: {dep_report.source_file}")
        for d in dep_report.dependencies:
            pin = f"=={d.version}" if d.version else " (unpinned)"
            typer.echo(f"  - {d.name}{pin}")
    else:
        typer.echo(f"  [INFO] {dep_report.note}")

    typer.echo("")
    typer.echo("Vulnerabilities (OSV)")
    osv_report = None
    if not dep_report.dependencies:
        typer.echo("  [INFO] No dependencies to check.")
    else:
        osv_report = query_osv(dep_report.dependencies)
        for err in osv_report.errors:
            typer.echo(f"  [ERROR] {err}")
        if osv_report.vulnerabilities:
            for v in osv_report.vulnerabilities:
                tag = _TAG.get(v.severity, "[????]")
                typer.echo(f"  {tag} {v.package}=={v.version} {v.vuln_id}: {v.summary}")
        elif not osv_report.errors:
            typer.echo(f"  [INFO] No known vulnerabilities in {osv_report.queried} pinned dependencies.")

    # Generate the ML-BOM if requested.
    if sbom:
        typer.echo("")
        typer.echo("ML-BOM (CycloneDX)")
        try:
            from types import SimpleNamespace
            osv_for_bom = osv_report or SimpleNamespace(vulnerabilities=[])
            bom_dict = build_mlbom(source, dep_report, osv_for_bom)
            write_mlbom(bom_dict, sbom)
            n_comp = len(bom_dict.get("components", []))
            n_vuln = len(bom_dict.get("vulnerabilities", []))
            typer.echo(f"  [INFO] Wrote {sbom} ({n_comp} components, {n_vuln} vulnerabilities).")
        except Exception as exc:  # noqa: BLE001
            typer.echo(f"  [ERROR] Could not generate ML-BOM: {exc}")
            raise typer.Exit(code=2)


if __name__ == "__main__":
    app()