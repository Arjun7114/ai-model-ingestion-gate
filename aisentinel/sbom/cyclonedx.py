"""Generate a CycloneDX ML-BOM from scan results."""

import json
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import Vulnerability as CdxVulnerability
from cyclonedx.model.vulnerability import VulnerabilitySource, BomTarget
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL


def build_mlbom(source, dep_report, osv_report) -> dict:
    """Assemble a CycloneDX BOM (as a dict) describing the model and its deps."""
    bom = Bom()

    # The model itself is the primary component of this BOM.
    model_component = Component(
        name=source.identifier,
        type=ComponentType.MACHINE_LEARNING_MODEL,
        version=source.revision or "unknown",
    )
    bom.metadata.component = model_component

    # Map dependency name -> component so we can attach vulnerabilities.
    dep_components: dict[str, Component] = {}
    for dep in dep_report.dependencies:
        purl = PackageURL(type="pypi", name=dep.name.lower(), version=dep.version)
        comp = Component(
            name=dep.name,
            type=ComponentType.LIBRARY,
            version=dep.version or "unknown",
            purl=purl,
        )
        bom.components.add(comp)
        dep_components[dep.name] = comp

    # Attach each OSV vulnerability to the component it affects.
    for v in osv_report.vulnerabilities:
        affected = dep_components.get(v.package)
        cdx_vuln = CdxVulnerability(
            id=v.vuln_id,
            source=VulnerabilitySource(name="OSV"),
            description=v.summary,
        )
        if affected is not None:
            cdx_vuln.affects = [BomTarget(ref=affected.bom_ref.value)]
        bom.vulnerabilities.add(cdx_vuln)

    # Serialize to a CycloneDX 1.6 JSON string, then back to a dict so the
    # caller can either print it or write it to a file.
    outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
    return json.loads(outputter.output_as_string())


def write_mlbom(bom_dict: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bom_dict, fh, indent=2)