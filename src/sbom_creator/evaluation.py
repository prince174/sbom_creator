"""Post-analysis reference evaluation. Never called by dependency classifiers."""
import hashlib
import json
from pathlib import Path

from jsonschema.exceptions import ValidationError
from packageurl import PackageURL

from .validation import validate_cyclonedx

LIMIT = 8 * 1024 * 1024


def validate_reference(document):
    if len(json.dumps(document).encode()) > LIMIT:
        raise ValueError('Reference exceeds evaluation budget')
    try:
        validate_cyclonedx(document)
    except ValidationError:
        raise ValueError('Invalid reference schema') from None
    return document


def identity(component):
    if not component.get('purl'):
        return None
    p = PackageURL.from_string(component['purl'])
    return (p.type, p.namespace, p.name, p.version)


def component_index(document):
    """Index nested CycloneDX components, including the metadata owner."""
    pending = list(document.get('components', []))
    root = document.get('metadata', {}).get('component')
    if root:
        pending.append(root)
    result = {}
    while pending:
        component = pending.pop()
        if component.get('bom-ref'):
            result[component['bom-ref']] = component
        pending.extend(component.get('components', []))
    return result


def compare(result_directory, reference, scope='unknown'):
    validate_reference(reference)
    path = Path(result_directory)
    actual_bom = json.loads((path / 'final.cdx.json').read_bytes())
    report = json.loads((path / 'direct-dependencies.json').read_bytes())
    root = reference.get('metadata', {}).get('component', {})
    owner = identity(root)
    expected_nodes = [n for n in reference.get('dependencies', []) if n['ref'] == root.get('bom-ref')]
    base = {'status': 'UNKNOWN', 'scope': scope, 'reference_build_binding': 'caller_asserted_not_attested',
            'reference_sha256': hashlib.sha256(json.dumps(reference, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'result_sha256': hashlib.sha256((path / 'final.cdx.json').read_bytes()).hexdigest(),
            'reference_used_as_analysis_input': False, 'precision': None, 'recall': None, 'f1': None}
    if scope != 'runtime' or owner is None or len(expected_nodes) != 1:
        return dict(base, reason='scope_or_reference_root_not_established')
    components = component_index(reference)
    if any(ref not in components for ref in expected_nodes[0].get('dependsOn', [])):
        return dict(base, reason='reference_dependency_target_unavailable')
    expected = {identity(components[ref]) for ref in expected_nodes[0].get('dependsOn', [])}
    actual_components = component_index(actual_bom)
    owners = {ref for ref, c in actual_components.items() if identity(c) == owner}
    if len(owners) != 1 or report.get('status') in ('UNKNOWN', 'not-applicable'):
        return dict(base, reason='analyzer_direct_owner_or_profile_unknown')
    edges = [e for e in report.get('edges', []) if e.get('status') == 'DIRECT' and e.get('owner_ref') in owners]
    if any(e.get('component_ref') not in actual_components for e in edges):
        return dict(base, reason='analyzer_dependency_target_unavailable')
    actual = {identity(actual_components[e['component_ref']]) for e in edges}
    if None in actual or None in expected:
        return dict(base, reason='package_identity_unavailable')
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    unknown = sum(e.get('status') == 'UNKNOWN' for e in report.get('edges', []))
    names = {p[:3] for p in actual} & {p[:3] for p in expected}
    version_correct = sum({p[3] for p in actual if p[:3] == name} ==
                          {p[3] for p in expected if p[:3] == name} for name in names)
    return dict(base, status='MEASURED', reason=None, tp=tp, fp=fp, fn=fn,
                reference_direct=len(expected), predicted_direct=len(actual),
                count_delta=len(actual) - len(expected),
                unknown_declarations=unknown,
                declaration_coverage=len(actual) / (len(actual) + unknown) if actual or unknown else None,
                missing=[list(p) for p in sorted(expected - actual, key=repr)],
                extra=[list(p) for p in sorted(actual - expected, key=repr)],
                version_accuracy=version_correct / len(names) if names else None,
                precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None,
                f1=2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None)
