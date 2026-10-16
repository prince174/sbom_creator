"""Bounded POM-only input for a passive Maven resolver; never execute a project."""
import hashlib
import os
import re
import stat
import xml.etree.ElementTree as ET
from pathlib import Path

NS = '{http://maven.apache.org/POM/4.0.0}'
MAX_POMS = 256
MAX_BYTES = 8 * 1024 * 1024
PER_POM = 1024 * 1024
SKIP = {'.git', 'node_modules', 'target', 'build', '.gradle'}


def parse(raw):
    text = raw.decode('utf-8-sig')
    if '\x00' in text or '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
        raise ValueError('POM declarations/entities are unsupported')
    root = ET.fromstring(text)
    if root.tag != NS + 'project':
        raise ValueError('Unsupported POM namespace')
    pending = [(root, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if depth > 64 or count > 20_000:
            raise ValueError('POM structure budget')
        pending.extend((child, depth + 1) for child in node)
    return root


def value(node, name, default=None):
    text = node.findtext(NS + name)
    return text.strip() if text is not None else default


def declaration(dep):
    return {name: (text if text is None or re.fullmatch(r'[A-Za-z0-9_.${}\[\](),+*-]{1,256}', text)
                   else '<unsupported>') for name in
            ('groupId', 'artifactId', 'version', 'scope', 'optional', 'type', 'classifier')
            for text in [value(dep, name)]}


def project(raw):
    root = parse(raw)
    profiles = []
    for profile in root.findall(NS + 'profiles/' + NS + 'profile'):
        profiles.append({'id': value(profile, 'id'), 'status': 'UNKNOWN',
                         'reason': 'build_profile_activation_not_observed',
                         'dependencies': [declaration(dep) for dep in
                            profile.findall(NS + 'dependencies/' + NS + 'dependency')]})
    declarations = []
    for dep in root.findall(NS + 'dependencies/' + NS + 'dependency'):
        declarations.append(declaration(dep))
        optional = dep.find(NS + 'optional')
        if optional is not None and (optional.text or '').strip() == 'true':
            optional.text = 'false'  # Include optional direct declarations, not their transitives.
    # No reactor containment edges and no profile activation guesses. Each POM
    # is analyzed as its own owner; local parent POMs remain at the same paths.
    for child in list(root):
        if child.tag in {NS + n for n in ('modules', 'profiles', 'repositories', 'pluginRepositories', 'build', 'reporting')}:
            root.remove(child)
    for node in root.iter():
        if node.tag == NS + 'relativePath' and node.text:
            relative = node.text.strip().replace('\\', '/')
            if relative.startswith('/') or ':' in relative:
                raise ValueError('Absolute parent path unsupported')
    return ET.tostring(root, encoding='utf-8', xml_declaration=True), declarations, profiles


def prepare(checkout, destination):
    root = Path(checkout).resolve()
    trace, total, visited = [], 0, 0
    for directory, names, files in os.walk(root, followlinks=False):
        visited += 1
        if visited > 10_000:
            raise ValueError('POM traversal budget')
        names[:] = sorted(n for n in names if n not in SKIP and not (Path(directory) / n).is_symlink())
        if 'pom.xml' not in files:
            continue
        path = Path(directory) / 'pom.xml'
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or path.is_symlink() or info.st_size > PER_POM:
            raise ValueError('Unsafe POM')
        raw = path.read_bytes()
        total += len(raw)
        if len(raw) > PER_POM or total > MAX_BYTES or len(trace) >= MAX_POMS:
            raise ValueError('POM byte/count budget')
        relative = path.relative_to(root).as_posix()
        projected, declarations, profiles = project(raw)
        target = Path(destination) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(projected)
        trace.append({'path': relative, 'sha256': hashlib.sha256(raw).hexdigest(),
                      'projection_sha256': hashlib.sha256(projected).hexdigest(),
                      'declarations': declarations, 'profiles': profiles})
    # Local parent lookup may never leave the POM-only sandbox. Even a default
    # ../pom.xml at the root is replaced with an explicit nonexistent safe path.
    for item in trace:
        path = Path(destination) / item['path']
        pom = parse(path.read_bytes())
        parent = pom.find(NS + 'parent')
        if parent is not None:
            relative = parent.find(NS + 'relativePath')
            target = (path.parent / ((relative.text or '').strip() if relative is not None else '../pom.xml')).resolve()
            if target.is_dir() and not (relative is not None and not (relative.text or '').strip()):
                target = target / 'pom.xml'
            if not target.is_relative_to(Path(destination).resolve()) or not target.is_file():
                if relative is None:
                    relative = ET.SubElement(parent, NS + 'relativePath')
                relative.text = '__sbom_missing_parent__.xml'
            path.write_bytes(ET.tostring(pom, encoding='utf-8', xml_declaration=True))
            item['projection_sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()
    return trace


def seed_local_poms(source, home, trace):
    """Expose literal local reactor POMs to Trivy's existing BOM/parent resolver.

    Only current source POMs, never reference build cache, artifacts or effective
    models. Expressions and duplicate GAVs are deliberately not guessed.
    """
    records = {}
    ambiguous = set()
    for item in trace:
        root = parse((Path(source) / item['path']).read_bytes())
        parent = root.find(NS + 'parent')
        group = value(root, 'groupId') or (value(parent, 'groupId') if parent is not None else None)
        version = value(root, 'version') or (value(parent, 'version') if parent is not None else None)
        artifact = value(root, 'artifactId')
        parts = (group, artifact, version)
        if not all(isinstance(p, str) and re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,255}', p)
                   and p not in ('.', '..') for p in parts):
            continue
        if parts in records:
            ambiguous.add(parts)
        if parent is not None:
            relative = parent.find(NS + 'relativePath')
            if relative is None:
                relative = ET.SubElement(parent, NS + 'relativePath')
            relative.text = '__sbom_missing_parent__.xml'
        records[parts] = ET.tostring(root, encoding='utf-8', xml_declaration=True)
    seeded = []
    for (group, artifact, version), data in sorted(records.items()):
        if (group, artifact, version) in ambiguous:
            continue
        target = Path(home) / '.m2/repository' / group.replace('.', '/') / artifact / version / (artifact+'-'+version+'.pom')
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        seeded.append({'coordinate': [group, artifact, version], 'sha256': hashlib.sha256(data).hexdigest()})
    return seeded
