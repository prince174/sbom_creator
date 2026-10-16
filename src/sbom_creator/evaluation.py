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


def component_metrics(actual_bom, reference, scope):
    """Compare supplied inventory scopes independently from graph availability.

    Only an explicitly runtime-scoped reference can label delivered inventory.
    Build scope instead compares the separate analysis-environment build model.
    Identities retain PURL qualifiers/subpaths, and metadata subjects are excluded
    even when a producer also lists its subject in the component collection.
    """
    base = {'status': 'UNKNOWN', 'scope': scope, 'precision': None, 'recall': None, 'f1': None,
            'version_accuracy': None, 'exact_version_coverage': None,
            'unit': 'unique_exact_purl', 'reference_used_as_analysis_input': False,
            'reference_scope_binding': 'caller_asserted_not_attested',
            'original_build_reproduced': False}
    if scope not in ('runtime', 'build'):
        return dict(base, reason='reference_component_scope_not_established')

    def inventory(document):
        root = document.get('metadata', {}).get('component', {})
        root_ref = root.get('bom-ref')
        root_purl = None
        if root.get('purl'):
            try:
                root_purl = PackageURL.from_string(root['purl']).to_string()
            except ValueError:
                pass
        pending = list(document.get('components', [])) + list(root.get('components', []))
        identities, unknown, labelled = set(), 0, 0
        while pending:
            component = pending.pop()
            pending.extend(component.get('components', []))
            if root_ref and component.get('bom-ref') == root_ref:
                continue
            try:
                parsed = PackageURL.from_string(component.get('purl', ''))
                exact = parsed.to_string()
                if exact == root_purl:
                    continue
                # Versionless identifiers and contradictory coordinate fields
                # cannot establish an exact component/version match.
                names = {parsed.name, '/'.join(filter(None, (parsed.namespace, parsed.name)))}
                if (not parsed.version or component.get('version') != parsed.version
                        or component.get('name') not in names
                        or component.get('group', parsed.namespace) != parsed.namespace):
                    raise ValueError('Incomplete or contradictory component identity')
            except (ValueError, TypeError, AttributeError):
                unknown += 1
                continue
            labelled += 1
            identities.add(exact)
        return identities, unknown, labelled

    actual, actual_unknown, actual_labelled = inventory(actual_bom)
    expected, expected_unknown, expected_labelled = inventory(reference)
    details = {'reference_components': len(expected), 'predicted_components': len(actual),
               'count_delta': len(actual)-len(expected),
               'reference_unknown_components': expected_unknown,
               'predicted_unknown_components': actual_unknown,
               'reference_identity_coverage': expected_labelled/(expected_labelled+expected_unknown)
                   if expected_labelled+expected_unknown else None,
               'predicted_identity_coverage': actual_labelled/(actual_labelled+actual_unknown)
                   if actual_labelled+actual_unknown else None,
               'reference_duplicate_identity_instances': expected_labelled-len(expected),
               'predicted_duplicate_identity_instances': actual_labelled-len(actual),
               'comparison_model': 'delivered_inventory' if scope == 'runtime' else 'analysis_environment_build_model'}
    if expected_unknown or actual_unknown:
        return dict(base, **details, reason='component_identity_or_exact_version_unavailable')
    if not expected:
        return dict(base, **details, reason='reference_components_empty')
    tp, fp, fn = len(actual & expected), len(actual-expected), len(expected-actual)
    def versions(identities):
        result = {}
        for exact in identities:
            parsed = PackageURL.from_string(exact)
            name = parsed._replace(version=None).to_string()
            result.setdefault(name, set()).add(parsed.version)
        return result
    actual_versions, expected_versions = versions(actual), versions(expected)
    shared_names = actual_versions.keys() & expected_versions.keys()
    correct_versions = sum(actual_versions[name] == expected_versions[name] for name in shared_names)
    return dict(base, **details, status='MEASURED', reason=None, tp=tp, fp=fp, fn=fn,
                precision=tp/(tp+fp) if tp+fp else None, recall=tp/(tp+fn),
                f1=2*tp/(2*tp+fp+fn), exact_version_coverage=tp/len(expected),
                version_accuracy=correct_versions/len(shared_names) if shared_names else None,
                missing=sorted(expected-actual), extra=sorted(actual-expected))


def compare(result_directory, reference, scope='unknown'):
    validate_reference(reference)
    path = Path(result_directory)
    filename = 'build.cdx.json' if scope == 'build' else 'final.cdx.json'
    report_name = 'java-direct-dependencies.json' if scope == 'build' else 'direct-dependencies.json'
    if not (path/filename).is_file():
        return {'status': 'UNKNOWN', 'scope': scope, 'reason': 'build_model_unavailable',
                'reference_used_as_analysis_input': False, 'precision': None, 'recall': None, 'f1': None,
                'components': {'status': 'UNKNOWN', 'scope': scope, 'reason': 'result_inventory_unavailable',
                               'precision': None, 'recall': None, 'f1': None}}
    actual_bom = json.loads((path / filename).read_bytes())
    report = (json.loads((path / report_name).read_bytes()) if (path/report_name).is_file()
              else {'status': 'UNKNOWN', 'edges': []})
    root = reference.get('metadata', {}).get('component', {})
    owner = identity(root)
    expected_nodes = [n for n in reference.get('dependencies', []) if n['ref'] == root.get('bom-ref')]
    base = {'status': 'UNKNOWN', 'scope': scope, 'reference_build_binding': 'caller_asserted_not_attested',
            'reference_sha256': hashlib.sha256(json.dumps(reference, sort_keys=True, separators=(',', ':')).encode()).hexdigest(),
            'result_sha256': hashlib.sha256((path / filename).read_bytes()).hexdigest(),
            'reference_used_as_analysis_input': False, 'precision': None, 'recall': None, 'f1': None,
            'components': component_metrics(actual_bom, reference, scope)}
    if scope not in ('runtime', 'build') or owner is None or len(expected_nodes) != 1:
        return dict(base, reason='scope_or_reference_root_not_established')
    components = component_index(reference)
    if any(ref not in components for ref in expected_nodes[0].get('dependsOn', [])):
        return dict(base, reason='reference_dependency_target_unavailable')
    expected = {identity(components[ref]) for ref in expected_nodes[0].get('dependsOn', [])}
    actual_components = component_index(actual_bom)
    owners = {ref for ref, c in actual_components.items() if identity(c) == owner}
    if len(owners) != 1 or report.get('status') in ('UNKNOWN', 'not-applicable'):
        return dict(base, reason='analyzer_direct_owner_or_profile_unknown')
    owner_field, target_field = ('build_owner_ref', 'build_component_ref') if scope == 'build' else ('owner_ref', 'component_ref')
    edges = [e for e in report.get('edges', []) if e.get('status') == 'DIRECT' and e.get(owner_field) in owners]
    if any(e.get(target_field) not in actual_components for e in edges):
        return dict(base, reason='analyzer_dependency_target_unavailable')
    actual = {identity(actual_components[e[target_field]]) for e in edges}
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
