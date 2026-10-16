"""Experimental image identity adapter, with no reference/build-graph access.

Join only a unique Maven identity at an exact final archive path and layer in
two catalogs of the same config digest. Bounded payload witnesses remain an
independent prerequisite. This produces inventory, never owner/direct edges.
"""
from __future__ import annotations

import copy
import posixpath
import re
from collections import defaultdict

from packageurl import PackageURL

from ..core import artifact_identity

DIGEST = re.compile(r'sha256:[a-f0-9]{64}')
PREFIX = 'aquasecurity:trivy:'


def properties(component, name):
    return [p.get('value') for p in component.get('properties', []) if p.get('name') == PREFIX + name]


def canonical_path(value):
    if (not isinstance(value, str) or not value or value.startswith('//') or '\\' in value or ':' in value
            or any(ord(c) < 32 for c in value) or any(p in ('.', '..', '') for p in value.lstrip('/').split('/'))):
        raise ValueError('Noncanonical archive path')
    result = '/' + value.lstrip('/')
    if result.startswith('//') or posixpath.normpath(result) != result:
        raise ValueError('Noncanonical archive path')
    return result


def maven_identity(component):
    purl = PackageURL.from_string(component.get('purl', ''))
    probe = {'purl': purl.to_string(), 'type': 'java-archive',
             'name': component.get('name'), 'version': component.get('version')}
    valid = artifact_identity(probe)
    if (not valid['identity_valid'] or purl.type != 'maven'
            or component.get('group', purl.namespace) != purl.namespace):
        raise ValueError('Incomplete or conflicting Maven identity')
    return purl


def artifact_key(artifact, files):
    candidates = []
    virtual = artifact.get('metadata', {}).get('virtualPath')
    for location in artifact.get('locations', []):
        outer = canonical_path(location.get('path', ''))
        layer = location.get('layerID', '')
        if not DIGEST.fullmatch(layer):
            raise ValueError('Missing layer identity')
        entries = files.get(outer, [])
        if len(entries) != 1:
            raise ValueError('Ambiguous or absent final file')
        entry = entries[0]
        if (entry['location'].get('layerID') != layer or entry.get('metadata', {}).get('type') != 'RegularFile'
                or entry.get('metadata', {}).get('size', 0) <= 0):
            raise ValueError('Final file layer/type mismatch')
        target = virtual if virtual is not None else outer
        if target == outer:
            path = outer
        elif isinstance(target, str) and target.startswith(outer + ':'):
            nested = target[len(outer) + 1:].split(':')
            if len(nested) > 8:
                raise ValueError('Nested depth unsupported')
            path = outer + '/' + '/'.join(canonical_path(part).lstrip('/') for part in nested)
        else:
            raise ValueError('Virtual archive path differs from final file')
        access = location.get('accessPath')
        if access is not None and access != target:
            raise ValueError('Conflicting access path')
        candidates.append((path, layer))
    if len(candidates) != 1:
        raise ValueError('Ambiguous archive location')
    return candidates[0]


def bridge(image, trivy, witnesses):
    config = image.get('source', {}).get('metadata', {}).get('imageID', '')
    peer_ids = properties(trivy.get('metadata', {}).get('component', {}), 'ImageID')
    if not DIGEST.fullmatch(config) or peer_ids != [config]:
        raise ValueError('Image config identity absent, ambiguous or mismatched')
    result = copy.deepcopy(image)
    evidence = copy.deepcopy(witnesses)
    files = defaultdict(list)
    for entry in image.get('files', []):
        try:
            files[canonical_path(entry.get('location', {}).get('path', ''))].append(entry)
        except ValueError:
            continue
    peer = defaultdict(list)
    ignored = []
    pending = list(trivy.get('components', []))
    count = 0
    while pending:
        component = pending.pop()
        pending.extend(component.get('components', []))
        count += 1
        if count > 100_000:
            raise ValueError('Peer component count budget')
        if not component.get('purl', '').startswith('pkg:maven/'):
            continue
        paths = properties(component, 'FilePath')
        layers = properties(component, 'LayerDiffID')
        try:
            if len(paths) != 1 or len(layers) != 1 or not DIGEST.fullmatch(layers[0]):
                raise ValueError('Peer archive location ambiguous')
            key = canonical_path(paths[0]), layers[0]
            identity = maven_identity(component)
        except (ValueError, TypeError, AttributeError) as error:
            ignored.append({'ref': component.get('bom-ref'), 'reason': str(error)})
            continue
        peer[key].append(identity)
    syft = defaultdict(list)
    keys, errors = {}, {}
    for artifact in image.get('artifacts', []):
        if artifact.get('foundBy') != 'java-archive-cataloger':
            continue
        try:
            key = artifact_key(artifact, files)
            keys[artifact['id']] = key
            syft[key].append(artifact['id'])
        except (ValueError, KeyError, TypeError) as error:
            errors[artifact['id']] = str(error)
    audit = []
    for artifact in result.get('artifacts', []):
        if artifact.get('foundBy') != 'java-archive-cataloger':
            continue
        original = {field: artifact.get(field) for field in ('id', 'purl', 'name', 'version')}
        key = keys.get(artifact['id'])
        reason = errors.get(artifact['id'])
        if key is not None and (len(syft[key]) != 1 or len(peer[key]) != 1):
            reason = 'Archive path/layer does not identify one package in each engine'
        witness = witnesses.get(artifact['id'], {})
        if witness.get('status') != 'confirmed' or not witness.get('path'):
            reason = reason or 'No bounded class/resource witness'
        elif key is not None:
            virtual = artifact.get('metadata', {}).get('virtualPath', artifact['locations'][0]['path'])
            if not witness['path'].startswith(virtual + ':'):
                reason = 'Payload witness belongs to another archive'
        if key is None or reason:
            evidence[artifact['id']] = {**witness, 'status': 'unconfirmed',
                                       'identity_bridge_unknown': reason or 'Unbound package'}
            audit.append({'original': original, 'status': 'UNKNOWN', 'reason': reason,
                          'path_layer': key, 'observed_payload': witness})
            continue
        identity = peer[key][0]
        artifact.update(purl=identity.to_string(), name=identity.name, version=identity.version)
        audit.append({'original': original, 'status': 'BOUND', 'identity': identity.to_string(),
                      'path_layer': key, 'observed_payload': witness})
    return result, evidence, {'image_config_digest': config, 'packages': audit,
                              'ignored_peer': ignored, 'scope': 'Image inventory; no directness or runtime-use claim'}
