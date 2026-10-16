"""Bind complete archive facts to an exact image instance and Maven identity."""
import copy
import re
import sqlite3
import zipfile
import zlib
from collections import defaultdict

from .trivy_payload_bridge import (
    DIGEST,
    artifact_key,
    canonical_path,
    maven_identity,
    properties,
)

HASH = re.compile(r'[a-f0-9]{64}')
SHA1 = re.compile(r'[a-f0-9]{40}')
POLICY = 'verified-java-archive-component-v1'


def valid_fact(artifact, proof, files, config, *, database_sha256=None):
    """Structural validation of internal, already verified physical facts."""
    try:
        key = artifact_key(artifact, files)
        virtual = artifact.get('metadata', {}).get('virtualPath', artifact['locations'][0]['path'])
        identity = maven_identity(artifact).to_string()
        return (proof.get('status') == 'confirmed' and proof.get('kind') == 'complete_java_archive'
                and proof.get('identity') == identity and proof.get('chain_verified') is True
                and proof.get('zip_crc_verified') is True
                and proof.get('nested_crc_verified') is (':' in virtual)
                and proof.get('image_config_digest') == config and DIGEST.fullmatch(config)
                and [proof.get('path'), proof.get('layer')] == list(key)
                and proof.get('virtual_path') == virtual
                and type(proof.get('bytes')) is int and 0 < proof['bytes'] <= 128*1024**2
                and isinstance(proof.get('sha256'), str) and HASH.fullmatch(proof['sha256'])
                and isinstance(proof.get('sha1'), str) and SHA1.fullmatch(proof['sha1'])
                and ((proof.get('identity_method') == 'canonical_maven_properties'
                      and proof.get('metadata_identity') == identity)
                     or (proof.get('identity_method') == 'public_java_db_full_sha1'
                         and proof.get('public_hash_association', {}).get('purl') == identity
                         and proof['public_hash_association'].get('sha1') == proof['sha1']
                         and proof['public_hash_association'].get('archive_type') == 'jar'
                         and proof['public_hash_association'].get('lookup') == 'exact_full_archive_sha1_blob'
                         and proof['public_hash_association'].get('publisher_authenticated') is False
                         and proof['public_hash_association'].get('globally_unique_gav_proven') is False
                         and proof['public_hash_association'].get('database_sha256') == database_sha256
                         and isinstance(proof['public_hash_association'].get('database_sha256'), str)
                         and HASH.fullmatch(proof['public_hash_association']['database_sha256']))))
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def bind(original, adapted, peer, witnesses, files, *, lookup=None):
    """No guessed aliases, global PURL match, or promotion by payload reason."""
    config = original.get('source', {}).get('metadata', {}).get('imageID', '')
    if (not DIGEST.fullmatch(config) or files.layers_reader.config_digest != config
            or properties(peer.get('metadata', {}).get('component', {}), 'ImageID') != [config]):
        raise ValueError('Archive component image binding differs')
    final, source_paths, peer_paths = defaultdict(list), defaultdict(list), defaultdict(list)
    for entry in original.get('files', []):
        final[entry.get('location', {}).get('path')].append(entry)
    for artifact in original['artifacts']:
        if artifact.get('foundBy') != 'java-archive-cataloger':
            continue
        try:
            source_paths[artifact_key(artifact, final)].append(artifact)
        except (ValueError, KeyError, TypeError):
            continue
    pending = list(peer.get('components', []))
    count = 0
    while pending:
        component = pending.pop()
        pending.extend(component.get('components', []))
        count += 1
        if count > 100_000:
            raise ValueError('Peer archive component count budget')
        if not component.get('purl', '').startswith('pkg:maven/'):
            continue
        try:
            paths, layers = properties(component, 'FilePath'), properties(component, 'LayerDiffID')
            if len(paths) != 1 or len(layers) != 1 or not DIGEST.fullmatch(layers[0]):
                continue
            peer_paths[canonical_path(paths[0]), layers[0]].append(maven_identity(component))
        except (ValueError, TypeError, AttributeError):
            continue
    result, proofs, audit = copy.deepcopy(adapted), {}, []
    by_id = {a['id']: a for a in result['artifacts']}
    previous_by_id = {a['id']: a for a in adapted['artifacts']}
    claims = defaultdict(set)
    for key, artifacts in source_paths.items():
        if len(artifacts) != 1 or len(peer_paths[key]) != 1:
            continue
        artifact, identity = artifacts[0], peer_paths[key][0]
        aid = artifact['id']
        if witnesses.get(aid, {}).get('status') == 'confirmed':
            continue
        row = {'artifact_id': aid, 'path_layer': list(key), 'status': 'UNKNOWN'}
        audit.append(row)
        try:
            proof = files.component(artifact)
            expected = identity.to_string()
            claims[proof['sha256']].add(expected)
            metadata_identity = proof.get('metadata_identity')
            association = lookup.lookup(proof['sha1']) if lookup is not None else None
            if metadata_identity is not None and metadata_identity != expected:
                row['reason'] = 'EMBEDDED_IDENTITY_CONFLICT'
                continue
            if association is not None and association['purl'] != expected:
                row['reason'] = 'PUBLIC_HASH_IDENTITY_CONFLICT'
                continue
            if metadata_identity is None and association is None:
                row['reason'] = 'NO_ARCHIVE_IDENTITY_PROOF'
                continue
            proof.update(identity=expected,
                identity_method=('canonical_maven_properties' if metadata_identity is not None
                                 else 'public_java_db_full_sha1'),
                public_hash_association=association)
            target = copy.deepcopy(by_id[aid])
            target.update(purl=expected, name=identity.name, version=identity.version)
            if not valid_fact(target, proof, final, config,
                              database_sha256=lookup.sha256 if lookup is not None else None):
                raise ValueError('Complete archive fact did not validate')
            by_id[aid].update(purl=expected, name=identity.name, version=identity.version)
            proofs[aid] = proof
            row.update(status='BOUND_ARCHIVE_COMPONENT', identity=expected, archive_presence=proof)
        except (ValueError, KeyError, TypeError, OSError, RuntimeError, sqlite3.Error,
                zipfile.BadZipFile, zlib.error, NotImplementedError) as error:
            row['reason'] = type(error).__name__
    # The public DB records only one association per SHA1. If this image exposes
    # multiple claimed identities for identical bytes, keep all of them UNKNOWN.
    rejected = {aid for aid, proof in proofs.items() if len(claims[proof['sha256']]) != 1}
    for aid in rejected:
        proofs.pop(aid)
        by_id[aid].update({field: previous_by_id[aid].get(field)
                          for field in ('purl', 'name', 'version')})
    for row in audit:
        if row['artifact_id'] in rejected:
            row.update(status='UNKNOWN', reason='SAME_BYTES_MULTIPLE_IDENTITIES')
    files.stats['archive_components_confirmed'] += len(proofs)
    return result, proofs, audit
