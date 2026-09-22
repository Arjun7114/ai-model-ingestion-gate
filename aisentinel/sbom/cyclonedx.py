"""Generate a CycloneDX ML-BOM from scan results."""

import os
import json
import warnings

from cyclonedx.model.bom import Bom
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.vulnerability import Vulnerability as CdxVulnerability
from cyclonedx.model.vulnerability import VulnerabilitySource, BomTarget
from cyclonedx.output import make_outputter
from cyclonedx.schema import OutputFormat, SchemaVersion
from packageurl import PackageURL


def _clean_model_name(source) -> str:
    """Use a clean basename for local paths; keep hub ids as-is."""
    if source.kind == "local":
        return os.path.basename(os.path.normpath(source.identifier))
    return source.identifier


def build_mlbom(source, dep_report, osv_report) -> dict:
    """Assemble a CycloneDX BOM (as a dict) describing the model and its deps."""
    bom = Bom()

    # The model itself is the primary component of this BOM.
    model_component = Component(
        name=_clean_model_name(source),
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
        # Register each dependency as a dependency of the root model component.
        bom.register_dependency(model_component, [comp])
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
            ref_value = getattr(affected.bom_ref, "value", None) or affected.bom_ref
            cdx_vuln.affects = [BomTarget(ref=ref_value)]
        bom.vulnerabilities.add(cdx_vuln)

    # Serialize to CycloneDX 1.6 JSON. Suppress the incomplete-graph warning,
    # which we address by registering dependencies above.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        outputter = make_outputter(bom, OutputFormat.JSON, SchemaVersion.V1_6)
        return json.loads(outputter.output_as_string())


def write_mlbom(bom_dict: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bom_dict, fh, indent=2)