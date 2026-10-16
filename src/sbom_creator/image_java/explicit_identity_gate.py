"""Service identity gate, independent of observed physical payload.

The audit is trusted in-process adapter output, never a request parameter.
Envelopes bind that output to the complete adapted catalog and physical facts.
Only the service's image adapter creates this envelope; it is not an API input.
"""
import copy
from collections import Counter, defaultdict

from ..core import build_candidates as base_candidates
from ..core import checksum
from .archive_component_identity import POLICY as ARCHIVE_POLICY
from .archive_component_identity import valid_fact as valid_archive_fact
from .trivy_payload_bridge import DIGEST, artifact_key

PRODUCERS = {'java-archive-cataloger', 'trivy-java-archive-cataloger'}


def prepare(image, audit):
    """Retain actual payload observations, and separately seal binding decisions."""
    config = image.get('source', {}).get('metadata', {}).get('imageID')
    original = audit['existing_bridge']
    if not isinstance(config, str) or not DIGEST.fullmatch(config) or config != original['image_config_digest']:
        raise ValueError('Adapter audit belongs to another image')
    rows = defaultdict(list)
    for row in original['packages']:
        rows[row['original']['id']].append((row, 'BOUND', row.get('path_layer')))
    for row in audit['supplemental']:
        if row.get('artifact_id'):
            rows[row['artifact_id']].append((row, 'CORROBORATED_TRIVY_ONLY',
                                            [row.get('path'), row.get('layer')]))
    files = defaultdict(list)
    for entry in image.get('files', []):
        files[entry.get('location', {}).get('path')].append(entry)
    payload, bindings = {}, {}
    for artifact in image['artifacts']:
        if artifact.get('foundBy') not in PRODUCERS:
            continue
        aid = artifact['id']
        matches = rows[aid]
        decision = {'status': 'UNKNOWN', 'reason': 'Missing or duplicate trusted binding audit'}
        if len(matches) == 1:
            row, accepted, path_layer = matches[0]
            # A failed identity join must never rewrite observed physical truth.
            payload[aid] = copy.deepcopy(row.get('observed_payload', {}))
            try:
                key = artifact_key(artifact, files)
                producer_agrees = (accepted == 'BOUND') == (artifact['foundBy'] == 'java-archive-cataloger')
                bound = (producer_agrees and row['status'] == accepted and row.get('identity') == artifact.get('purl')
                         and list(key) == list(path_layer or []))
            except (ValueError, KeyError, TypeError):
                bound = False
            decision = {'status': 'BOUND' if bound else 'UNKNOWN',
                        'reason': None if bound else row.get('reason') or 'Identity/path/layer unbound'}
        bindings[aid] = decision
    return payload, {'catalog_sha256': checksum(image), 'payload_sha256': checksum(payload),
                     'image_config_digest': config, 'artifacts': bindings,
                     'scope': 'Identity corroboration only; no directness or execution claim'}


def candidates(source, image, payload, envelope):
    """Fail closed for stale envelopes; gate each observation, not its siblings."""
    if (envelope.get('catalog_sha256') != checksum(image)
            or envelope.get('payload_sha256') != checksum(payload)
            or envelope.get('image_config_digest') != image.get('source', {}).get('metadata', {}).get('imageID')):
        raise ValueError('Identity envelope catalog/image/payload mismatch')
    result = base_candidates(source, image, payload)
    archives = envelope.get('archive_presence', {})
    archive_policy = envelope.get('reader_policy') == ARCHIVE_POLICY
    if archive_policy and envelope.get('archive_presence_sha256') != checksum(archives):
        raise ValueError('Archive-presence envelope mismatch')
    files = defaultdict(list)
    for entry in image.get('files', []):
        files[entry.get('location', {}).get('path')].append(entry)
    counts = Counter(a['id'] for a in image['artifacts'])
    for candidate in result:
        for fact in candidate['evidence']:
            if fact['origin'] != 'image' or fact['artifact'].get('foundBy') not in PRODUCERS:
                continue
            binding = envelope['artifacts'].get(fact['artifact_id'], {'status': 'UNKNOWN'})
            fact['identity_binding'] = copy.deepcopy(binding)
            if fact['artifact']['foundBy'] == 'trivy-java-archive-cataloger':
                fact['payload'] = copy.deepcopy(payload.get(fact['artifact_id'], {'status': 'unconfirmed'}))
                fact['presence_kind'] = ('archive_metadata' if fact['payload'].get('status') == 'confirmed'
                                         and fact['payload'].get('path') else 'metadata_without_confirmed_payload')
            if binding.get('status') != 'BOUND' or counts[fact['artifact_id']] != 1:
                fact['presence_kind'] = 'metadata_without_confirmed_identity'
            proof = archives.get(fact['artifact_id']) if archive_policy else None
            if (proof is not None and counts[fact['artifact_id']] == 1
                    and fact['artifact'].get('foundBy') == 'java-archive-cataloger'
                    and valid_archive_fact(fact['artifact'], proof, files, envelope['image_config_digest'],
                                           database_sha256=envelope.get('archive_database_sha256'))):
                fact['archive_presence'] = copy.deepcopy(proof)
                fact['archive_identity_binding'] = {'status': 'BOUND', 'method': proof['identity_method']}
                fact['presence_kind'] = 'verified_archive_component'
            fact['id'] = checksum({key: value for key, value in fact.items() if key != 'id'})
    return result
