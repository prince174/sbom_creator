"""Experimental explicitly attributed Trivy-only archive packages, no oracle."""
from __future__ import annotations

import hashlib
import json
import zipfile
from collections import defaultdict

from bounded_jar_evidence import JarFiles
from registry_fixture import archive_config
from trivy_payload_bridge import DIGEST, bridge, canonical_path, maven_identity, properties

CATALOGER = 'trivy-java-archive-cataloger'
ARCHIVES = ('.jar', '.war', '.ear', '.zip')


def virtual_archive(target, outer):
    if target == outer:
        return outer
    if not target.startswith(outer + '/'):
        raise ValueError('No physical outer archive prefix')
    parts, current = [], []
    for item in target[len(outer) + 1:].split('/'):
        current.append(item)
        if item.lower().endswith(ARCHIVES):
            parts.append('/'.join(current))
            current = []
    if current or not parts or len(parts) > 8:
        raise ValueError('Target is not a bounded nested archive')
    return outer + ':' + ':'.join(parts)


def supplement(image, peer, witnesses, archive_path, *, temporary=None):
    result, evidence, original_audit = bridge(image, peer, witnesses)
    config = image['source']['metadata']['imageID']
    if archive_config(archive_path)[0] != config:
        raise ValueError('Physical archive config differs from both catalogs')
    final = defaultdict(list)
    for entry in image.get('files', []):
        try:
            final[canonical_path(entry.get('location', {}).get('path', ''))].append(entry)
        except ValueError:
            continue
    occupied, uncertain_outer = set(), set()
    for artifact in image.get('artifacts', []):
        if artifact.get('foundBy') != 'java-archive-cataloger':
            continue
        for location in artifact.get('locations', []):
            try:
                outer = canonical_path(location.get('path', ''))
                virtual = artifact.get('metadata', {}).get('virtualPath', outer)
                if virtual != outer and not virtual.startswith(outer + ':'):
                    raise ValueError('Inconsistent Syft archive path')
                occupied.add(canonical_path(virtual.replace(':', '/')))
            except (ValueError, TypeError, AttributeError):
                if isinstance(location.get('path'), str):
                    uncertain_outer.add(location['path'])
    candidates = defaultdict(list)
    pending = list(peer.get('components', []))
    while pending:
        component = pending.pop()
        pending.extend(component.get('components', []))
        if not component.get('purl', '').startswith('pkg:maven/'):
            continue
        paths, layers = properties(component, 'FilePath'), properties(component, 'LayerDiffID')
        if len(paths) != 1 or len(layers) != 1 or not isinstance(layers[0], str) or not DIGEST.fullmatch(layers[0]):
            continue
        try:
            path = canonical_path(paths[0])
            identity = maven_identity(component)
        except (ValueError, TypeError, AttributeError):
            continue
        candidates[path, layers[0]].append((component, identity))
    files, audit = None, []
    try:
        for (target, layer), packages in sorted(candidates.items()):
            if target in occupied:
                continue  # Never bypass a rejected or ambiguous Syft identity.
            row = {'path': target, 'layer': layer, 'status': 'UNKNOWN'}
            audit.append(row)
            if len(packages) != 1:
                row['reason'] = 'Multiple identities at peer archive path/layer'
                continue
            component, identity = packages[0]
            row['identity'] = identity.to_string()
            outers = [(name, entries[0]) for name, entries in final.items() if len(entries) == 1
                      and name.lower().endswith(ARCHIVES) and (target == name or target.startswith(name + '/'))
                      and entries[0].get('metadata', {}).get('type') == 'RegularFile'
                      and entries[0].get('metadata', {}).get('size', 0) > 0]
            if len(outers) != 1:
                row['reason'] = 'Physical final outer archive absent or ambiguous'
                continue
            outer, entry = outers[0]
            if outer in uncertain_outer or entry['location'].get('layerID') != layer:
                row['reason'] = 'Uncertain source archive or mismatched final layer'
                continue
            try:
                virtual = virtual_archive(target, outer)
                item_id = hashlib.sha256(json.dumps([CATALOGER, config, target, layer,
                                                     identity.to_string()]).encode()).hexdigest()[:32]
                item = {'id': item_id, 'name': identity.name, 'version': identity.version,
                        'purl': identity.to_string(), 'type': 'java-archive', 'language': 'java',
                        'foundBy': CATALOGER, 'licenses': [], 'cpes': [], 'metadataType': 'java-archive',
                        'metadata': {'virtualPath': virtual},
                        'locations': [{'path': outer, 'layerID': layer, 'accessPath': virtual}]}
                if files is None:
                    files = JarFiles(archive_path, image, temporary=temporary)
                observed = files.witness(item)
                if not observed:
                    row['reason'] = 'No class/resource bytes; metadata alone is insufficient'
                    continue
            except (ValueError, KeyError, OSError, RuntimeError, zipfile.BadZipFile) as error:
                row['reason'] = type(error).__name__
                continue
            if any(existing['id'] == item_id for existing in result['artifacts']):
                raise ValueError('Supplemental artifact ID collision')
            result['artifacts'].append(item)
            evidence[item_id] = {'status': 'confirmed', 'path': observed,
                                 'method': 'trivy-identity-final-layer-bounded-archive-v1',
                                 'scope': 'Some class/resource bytes; no directness or runtime-use proof'}
            row.update(status='CORROBORATED_TRIVY_ONLY', artifact_id=item_id,
                       producer='Trivy0.75.0', peer_ref=component.get('bom-ref'),
                       original_syft_artifact=None, observed_payload=evidence[item_id])
    finally:
        if files is not None:
            files.close()
    return result, evidence, {'existing_bridge': original_audit, 'supplemental': audit,
                              'resource_counters': files.stats if files is not None else None,
                              'runtime_changed': False, 'producer': CATALOGER}
