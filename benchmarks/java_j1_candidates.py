"""J1 experimental candidates: static model + owner and image corroboration."""
import xml.etree.ElementTree as ET

from java_gav_evidence import match
from java_local_management import project
from java_local_parent import NS, chain


def predict(blobs, module, source, image):
    model = project(blobs, module)
    if model['status'] == 'UNKNOWN':
        return {'status': 'UNKNOWN', 'reason': model['reason'], 'candidates': [], 'unknown_count': None}
    local = chain(blobs, module)
    owner = {}
    for path in reversed(local['chain']):
        root = ET.fromstring(blobs[path])
        for key in ('groupId', 'version'):
            value = root.findtext('m:' + key, namespaces=NS)
            if value:
                owner[key] = value.strip()
    owner['artifactId'] = ET.fromstring(blobs[module]).findtext('m:artifactId', namespaces=NS)
    coordinate = tuple(owner.get(k) for k in ('groupId', 'artifactId', 'version'))
    candidates = []
    unknown = 0
    for row in model['rows']:
        if row['scope'] not in ('compile', 'runtime'):
            continue
        evidence = match(source, image, coordinate, tuple(row['coordinate']), module)
        if evidence['status'] == 'CORROBORATED_CANDIDATE':
            candidates.append({'owner': coordinate, 'dependency': row['coordinate'],
                               'scope': row['scope'], 'evidence': evidence, 'direct_edge_proven': False})
        else:
            unknown += 1
    return {'status': 'EXPERIMENTAL_CANDIDATES', 'candidates': candidates,
            'unknown_count': unknown, 'static_model': model,
            'limitation': 'Settings/CLI/plugin effects unresolved; not production direct edges'}
