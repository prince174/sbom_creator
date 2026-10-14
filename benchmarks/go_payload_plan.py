"""Experimental preflight only; reject aggregate reads before a content scan."""
import json
import re

LIMIT = 32 * 1024 * 1024


def plan(document, paths):
    def unknown(reason):
        return {'status': 'UNKNOWN', 'reason': reason, 'paths': [], 'unknown_count': None}
    if not isinstance(document, dict):
        return unknown('invalid_document')
    if not isinstance(paths, list) or any(not isinstance(p, str) for p in paths) or len(paths) > 8 or len(paths) != len(set(paths)):
        return unknown('invalid_or_excessive_targets')
    if not paths:
        return {'status': 'NOT_APPLICABLE', 'paths': []}
    if any(not isinstance(p, str) or not re.fullmatch(r'/[A-Za-z0-9_./-]+', p)
           or any(part in ('', '.', '..') for part in p.split('/')[1:]) for p in paths):
        return unknown('unsupported_path')
    files = document.get('files')
    if not isinstance(files, list):
        return unknown('missing_file_inventory')
    entries = {}
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get('location'), dict):
            return unknown('invalid_file_entry')
        path = entry['location'].get('path')
        if not isinstance(path, str) or path in entries:
            return unknown('ambiguous_file_inventory')
        entries[path] = entry
    total = 0
    encoded = 0
    for path in paths:
        meta = entries.get(path, {}).get('metadata', {})
        if not isinstance(meta, dict) or meta.get('type') != 'RegularFile':
            return unknown('nonregular_or_missing_binary')
        size = meta.get('size')
        if type(size) is not int or size <= 0 or size > LIMIT:
            return unknown('invalid_or_oversized_binary')
        total += size
        encoded += 4 * ((size + 2) // 3)
    if total > LIMIT:
        return unknown('aggregate_binary_budget')
    # Existing scan has already passed the runtime JSON size limit. This is not
    # a parser-memory bound; four MiB allow for fresh scan configuration/fields.
    metadata = len(json.dumps(document, ensure_ascii=False).encode('utf-8'))
    estimate = metadata + encoded + 4 * 1024 * 1024
    if metadata > 16 * 1024 * 1024 or estimate > 64 * 1024 * 1024:
        return unknown('serialized_output_budget')
    return {'status': 'PLANNED', 'paths': paths, 'decoded_bytes': total,
            'base64_bytes': encoded, 'estimated_output_bytes': estimate}
