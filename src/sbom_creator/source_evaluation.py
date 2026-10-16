"""Post-only evaluation of an already published source SBOM.

This module never invokes an analyzer, resolves a package, or changes predictions.
Both qualifier-sensitive and coordinate-only views remain visible; neither is an
attestation of the original CI environment or a claim about image presence.
"""
from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema.exceptions import ValidationError
from packageurl import PackageURL

from .acquire import validate_commit
from .evaluation import validate_reference
from .validation import validate_cyclonedx

SOURCE_LIMIT = 64 * 1024 * 1024
PROVENANCE_LIMIT = 1024 * 1024
PRODUCER_VERSION = '13.4.0'
VIEW_UNITS = {'exact_purl': 'unique_exact_purl',
              'coordinates': 'unique_ecosystem_namespace_name_exact_version'}


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key')
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError('Non-JSON constant')


def _read(path, limit):
    absolute = Path(path).absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError('Linked source result')
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError('Source result must be an owned regular file')
    with absolute.open('rb') as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError('Source result exceeds evaluation budget')
    return json.loads(raw, object_pairs_hook=_unique, parse_constant=_reject_constant), hashlib.sha256(raw).hexdigest()


def _source(directory, reference_commit):
    root = Path(directory)
    document, document_sha = _read(root / 'source.cdx.json', SOURCE_LIMIT)
    provenance, provenance_sha = _read(root / 'source-provenance.json', PROVENANCE_LIMIT)
    summary, summary_sha = _read(root / 'source-summary.json', PROVENANCE_LIMIT)
    validate_cyclonedx(document)
    producers = [item for item in document.get('metadata', {}).get('tools', {}).get('components', [])
                 if item.get('name') == 'cdxgen']
    engine = provenance.get('engine', {})
    parsed = urlsplit(provenance.get('repository_url', ''))
    commit = validate_commit(provenance.get('commit', ''))
    if (len(producers) != 1 or producers[0].get('version') != PRODUCER_VERSION
            or engine.get('name') != 'cdxgen' or engine.get('version') != PRODUCER_VERSION
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', engine.get('image_id', ''))
            or parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or not parsed.path.strip('/')
            or len(provenance['repository_url']) > 2048
            or any(character.isspace() or ord(character) < 32 for character in provenance['repository_url'])
            or '\\' in provenance['repository_url']
            or provenance.get('source_sbom_sha256') != document_sha
            or provenance.get('requested_commit', commit) != commit
            or summary.get('status') != 'completed'):
        raise ValueError('Source binding is invalid')
    if reference_commit is not None and validate_commit(reference_commit) != commit:
        raise ValueError('Reference commit does not match source commit')
    return document, {'repository_url': provenance['repository_url'], 'commit': commit,
        'source_sbom_sha256': document_sha, 'source_provenance_sha256': provenance_sha,
        'source_summary_sha256': summary_sha, 'engine_image_id': engine['image_id'],
        'engine_version': PRODUCER_VERSION, 'binding': 'validated_published_source_provenance',
        'original_ci_build_reproduced': False}


def _identity(component):
    try:
        parsed = PackageURL.from_string(component.get('purl', ''))
        names = {parsed.name, '/'.join(filter(None, (parsed.namespace, parsed.name)))}
        group = component.get('group', parsed.namespace)
        # CycloneDX permits an empty group for an unscoped package. PackageURL
        # represents that same absent namespace as None. This does not authorize
        # a missing or changed scoped namespace, aliases, or qualifier changes.
        if parsed.namespace is None and group == '':
            group = None
        if (parsed.type not in ('maven', 'npm') or component.get('name') not in names
                or group != parsed.namespace):
            return None, None
        name = parsed._replace(version=None).to_string()
        if not parsed.version or component.get('version') != parsed.version:
            return None, name
        return parsed.to_string(), name
    except (ValueError, TypeError, AttributeError):
        return None, None


def _view(purl, view, *, no_version=False):
    parsed = PackageURL.from_string(purl)
    if view == 'coordinates':
        parsed = parsed._replace(qualifiers={}, subpath=None)
    if no_version:
        parsed = parsed._replace(version=None)
    return parsed.to_string()


def _inventory(document):
    root = document.get('metadata', {}).get('component', {})
    root_identity, _ = _identity(root)
    pending = list(document.get('components', [])) + list(root.get('components', []))
    identities, names, unknown, known_instances = set(), set(), 0, 0
    while pending:
        component = pending.pop()
        pending.extend(component.get('components', []))
        if root.get('bom-ref') and component.get('bom-ref') == root['bom-ref']:
            continue
        identity, name = _identity(component)
        if root_identity is not None and identity == root_identity:
            continue
        if name:
            names.add(name)
        if identity is None:
            unknown += 1
        else:
            known_instances += 1
            identities.add(identity)
    return {'identities': identities, 'names': names, 'unknown': unknown,
            'known_instances': known_instances}


def _stats(actual, expected, actual_unknown, reference_unknown, scope, *, graph=False):
    result = {'status': 'UNKNOWN', 'reference_scope': scope,
        'predicted_count': len(actual), 'reference_count': len(expected),
        'count_delta': len(actual) - len(expected), 'predicted_unknown_observations': actual_unknown,
        'reference_unknown_observations': reference_unknown,
        'tp': None, 'fp': None, 'fn': None, 'precision': None, 'recall': None, 'f1': None,
        'conservative_precision_including_unknown': None, 'matched_version_accuracy': None,
        'exact_version_coverage': None, 'name_coverage': None, 'version_coverage': None,
        'missing': [], 'extra': []}
    if scope != 'build':
        return dict(result, reason='source_requires_explicit_build_reference_scope')
    if not expected:
        return dict(result, reason='reference_known_edges_empty' if graph else 'reference_known_components_empty',
                    tp=0, fp=len(actual), fn=0)
    tp, fp, fn = len(actual & expected), len(actual - expected), len(expected - actual)
    return dict(result, status='PARTIAL' if actual_unknown or reference_unknown else 'MEASURED',
        reason='unknown_observations_remain' if actual_unknown or reference_unknown else None,
        tp=tp, fp=fp, fn=fn, precision=tp / (tp + fp) if tp + fp else None,
        recall=tp / (tp + fn), f1=2 * tp / (2 * tp + fp + fn),
        conservative_precision_including_unknown=tp / (tp + fp + actual_unknown)
            if tp + fp + actual_unknown else None,
        exact_version_coverage=tp / len(expected), version_coverage=tp / len(expected))


def _version_metrics(actual, expected, observed_names, view, *, graph=False):
    def versions(values):
        result = {}
        for value in values:
            pair = value if graph else (value,)
            names = tuple(_view(item, view, no_version=True) for item in pair)
            version = tuple(PackageURL.from_string(item).version for item in pair)
            result.setdefault(names, set()).add(version)
        return result

    predicted, reference = versions(actual), versions(expected)
    common = predicted.keys() & reference.keys()
    correct = sum(predicted[name] == reference[name] for name in common)
    names = ({tuple(_view(item, view, no_version=True) for item in edge) for edge in observed_names}
             if graph else {(_view(name, view, no_version=True),) for name in observed_names})
    return {'matched_names': len(common), 'version_correct_matched_names': correct,
            'matched_version_accuracy': correct / len(common) if common else None,
            'name_coverage': len(names & reference.keys()) / len(reference) if reference else None}


def _variants(actual, expected):
    def index(values):
        result = {}
        for value in values:
            result.setdefault(_view(value, 'coordinates'), set()).add(value)
        return result
    predicted, reference = index(actual), index(expected)
    return [{'coordinate': name, 'predicted_purls': sorted(predicted.get(name, set())),
             'reference_purls': sorted(reference.get(name, set())),
             'exact_shared_purls': sorted(predicted.get(name, set()) & reference.get(name, set())),
             'variant_sets_differ': predicted.get(name, set()) != reference.get(name, set())}
            for name in sorted(predicted.keys() | reference.keys())]


def _component_views(actual, expected, scope):
    result = {}
    for view, unit in VIEW_UNITS.items():
        predicted = {_view(item, view) for item in actual['identities']}
        reference = {_view(item, view) for item in expected['identities']}
        stats = _stats(predicted, reference, actual['unknown'], expected['unknown'], scope)
        stats.update(unit=unit, reference_identity_coverage=expected['known_instances'] /
            (expected['known_instances'] + expected['unknown'])
                if expected['known_instances'] + expected['unknown'] else None,
            predicted_identity_coverage=actual['known_instances'] /
            (actual['known_instances'] + actual['unknown'])
                if actual['known_instances'] + actual['unknown'] else None,
            reference_duplicate_identity_instances=expected['known_instances'] - len(reference),
            predicted_duplicate_identity_instances=actual['known_instances'] - len(predicted))
        if scope == 'build':
            stats.update(missing=sorted(reference - predicted), extra=sorted(predicted - reference))
            if reference:
                stats.update(_version_metrics(predicted, reference, actual['names'], view))
        if view == 'coordinates':
            stats.update(claim='coordinate_agreement_not_full_package_identity',
                         exact_variant_details=_variants(actual['identities'], expected['identities']))
        result[view] = stats
    return result


def _graph(document, view):
    root = document.get('metadata', {}).get('component', {})
    index, pending = {}, list(document.get('components', [])) + [root]
    while pending:
        item = pending.pop()
        if item.get('bom-ref'):
            index[item['bom-ref']] = item
        pending.extend(item.get('components', []))
    rows = {row['ref']: row.get('dependsOn', []) for row in document.get('dependencies', [])}
    # Only explicitly structural metadata subjects are owners. Do not discover
    # modules from a library's image presence, filename or arbitrary graph node.
    subjects, pending = [], [root] if root else []
    while pending:
        item = pending.pop()
        subjects.append(item)
        pending.extend(item.get('components', []))
    owners, unknown_owners, unknown_edges = {}, 0 if root else 1, 0
    for subject in subjects:
        identity, _ = _identity(subject)
        targets = rows.get(subject.get('bom-ref'))
        if identity is None:
            unknown_owners += 1
            unknown_edges += len(targets) if targets is not None else 0
            continue
        owner = _view(identity, view)
        edges, unknown = set(), 0
        if targets is not None:
            for target_ref in targets:
                target, _ = _identity(index[target_ref])
                if target is None:
                    unknown += 1
                else:
                    edges.add((owner, _view(target, view)))
        owners.setdefault(owner, []).append({'edges': edges, 'unknown_edges': unknown,
                                            'graph_available': targets is not None})
    edges, missing_graph, ambiguous, known_owners = set(), [], [], {}
    for owner, observations in owners.items():
        if len(observations) != 1:
            ambiguous.append(owner)
            unknown_edges += sum(len(row['edges']) + row['unknown_edges'] for row in observations)
            continue
        row = observations[0]
        known_owners[owner] = row
        unknown_edges += row['unknown_edges']
        if row['graph_available']:
            edges.update(row['edges'])
        else:
            missing_graph.append(owner)
    return {'edges': edges, 'owners': known_owners, 'unknown_owners': unknown_owners,
            'unknown_edges': unknown_edges, 'missing_graph': missing_graph, 'ambiguous_owners': ambiguous}


def _edge_rows(edges):
    return [{'owner': owner, 'component': component} for owner, component in sorted(edges)]


def _graph_views(actual, expected, scope):
    result = {}
    for view, unit in VIEW_UNITS.items():
        predicted, reference = _graph(actual, view), _graph(expected, view)
        missing_owners = sorted(reference['owners'].keys() - predicted['owners'].keys())
        stats = _stats(predicted['edges'], reference['edges'], predicted['unknown_edges'],
                       reference['unknown_edges'], scope, graph=True)
        stats.update(unit='unique_structural_owner_to_component_' + unit,
            owner_semantics='CycloneDX_metadata_subjects_and_nested_subjects_only',
            inferred_build_declarations=False,
            predicted_unknown_owners=predicted['unknown_owners'],
            reference_unknown_owners=reference['unknown_owners'], missing_predicted_owners=missing_owners,
            predicted_graph_unavailable_owners=sorted(predicted['missing_graph']),
            reference_graph_unavailable_owners=sorted(reference['missing_graph']),
            predicted_ambiguous_owners=sorted(predicted['ambiguous_owners']),
            reference_ambiguous_owners=sorted(reference['ambiguous_owners']))
        if scope == 'build':
            stats.update(missing=_edge_rows(reference['edges'] - predicted['edges']),
                         extra=_edge_rows(predicted['edges'] - reference['edges']))
            if reference['edges']:
                stats.update(_version_metrics(predicted['edges'], reference['edges'], predicted['edges'], view, graph=True))
            if (missing_owners or predicted['missing_graph'] or predicted['ambiguous_owners']
                    or predicted['unknown_owners']):
                stats.update(status='UNKNOWN', reason='predicted_owner_or_graph_unavailable')
            elif reference['missing_graph'] or reference['ambiguous_owners'] or reference['unknown_owners']:
                stats.update(status='UNKNOWN', reason='reference_owner_or_graph_unavailable')
            stats['owners'] = []
            for owner in sorted(reference['owners'].keys() | predicted['owners'].keys()):
                expected_row = reference['owners'].get(owner, {'edges': set(), 'unknown_edges': 0})
                actual_row = predicted['owners'].get(owner, {'edges': set(), 'unknown_edges': 0})
                owner_stats = _stats(actual_row['edges'], expected_row['edges'], actual_row['unknown_edges'],
                                     expected_row['unknown_edges'], scope, graph=True)
                owner_stats.update(owner=owner, missing=_edge_rows(expected_row['edges'] - actual_row['edges']),
                    extra=_edge_rows(actual_row['edges'] - expected_row['edges']),
                    predicted_graph_available=actual_row.get('graph_available', False),
                    reference_graph_available=expected_row.get('graph_available', False),
                    predicted_target_identity_coverage=len(actual_row['edges']) /
                        (len(actual_row['edges']) + actual_row['unknown_edges'])
                        if actual_row['edges'] or actual_row['unknown_edges'] else None,
                    reference_target_identity_coverage=len(expected_row['edges']) /
                        (len(expected_row['edges']) + expected_row['unknown_edges'])
                        if expected_row['edges'] or expected_row['unknown_edges'] else None)
                if expected_row['edges']:
                    owner_stats.update(_version_metrics(actual_row['edges'], expected_row['edges'],
                                                        actual_row['edges'], view, graph=True))
                if owner not in predicted['owners'] or not actual_row.get('graph_available', False):
                    owner_stats.update(status='UNKNOWN', reason='predicted_owner_or_graph_unavailable')
                elif owner not in reference['owners'] or not expected_row.get('graph_available', False):
                    owner_stats.update(status='UNKNOWN', reason='reference_owner_or_graph_unavailable')
                stats['owners'].append(owner_stats)
            positive = [row for row in stats['owners'] if row['reference_count']]
            precision = [row['precision'] for row in positive if row['precision'] is not None]
            stats['owner_macro'] = {'positive_reference_owners': len(positive),
                'precision_defined_owners': len(precision),
                'precision': sum(precision) / len(precision) if precision else None,
                'recall': sum(row['recall'] for row in positive) / len(positive) if positive else None,
                'unknown_positive_reference_owners': sum(row['status'] == 'UNKNOWN' for row in positive),
                'empty_reference_owners_excluded': len(stats['owners']) - len(positive)}
        result[view] = stats
    return result


def evaluate_source(result_directory, reference, scope='unknown', reference_commit=None):
    """Evaluate sealed source output after analysis; invalid inputs raise ValueError.

    Reference scope/commit are caller assertions. Runtime/unknown scope produces
    an unscored report rather than assigning source components runtime precision.
    """
    try:
        if scope not in ('unknown', 'runtime', 'build'):
            raise ValueError('Invalid reference scope')
        validate_reference(reference)
        actual, binding = _source(result_directory, reference_commit)
        actual_inventory, expected_inventory = _inventory(actual), _inventory(reference)
        components = _component_views(actual_inventory, expected_inventory, scope)
        graph = _graph_views(actual, reference, scope)
        status = components['exact_purl']['status']
        return {'status': status, 'kind': 'source_reference_evaluation', 'schema_version': 1,
            'reference_scope': scope, 'reference_used_as_analysis_input': False,
            'analyzer_invoked': False, 'image_required': False, 'original_ci_graph_reproduced': False,
            'source_binding': binding,
            'reference_binding': {'provenance': 'caller_asserted_not_attested',
                'commit': validate_commit(reference_commit) if reference_commit is not None else None,
                'commit_matches_source': reference_commit is not None,
                'scope_attested': False,
                'sha256': hashlib.sha256(json.dumps(reference, sort_keys=True,
                    separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()},
            'components': components, 'direct_dependencies': graph,
            'limitations': ['known_labelled_build_scope_only', 'empty_and_unknown_not_success',
                'coordinate_view_does_not_establish_full_PURL_variant_identity',
                'structural_owner_graph_is_not_attestation_of_original_CI_profiles_or_declarations']}
    except (OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError, ValidationError):
        raise ValueError('Source verification inputs or binding are invalid') from None
