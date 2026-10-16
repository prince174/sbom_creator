"""Ready Trivy Maven resolver in an isolated POM-only workspace, no build tools."""
import hashlib
import json
import tempfile
import time
from collections import Counter
from pathlib import Path

from packageurl import PackageURL

from .acquire import clean_environment, run_command
from .java_inputs import prepare, seed_local_poms

VERSION = '0.75.0'
MIRRORS = {'https://repo.maven.apache.org/maven2/',
           'https://maven-central.storage-download.googleapis.com/maven2/'}


def coordinate(component):
    try:
        p = PackageURL.from_string(component.get('purl', ''))
        if (p.type != 'maven' or not p.namespace or not p.version or '${' in p.version
                or any(c in p.version for c in '[],()+') or p.name != component.get('name')
                or p.version != component.get('version')):
            return None
        return PackageURL(type='maven', namespace=p.namespace, name=p.name, version=p.version).to_string()
    except (ValueError, TypeError, AttributeError):
        return None


def extract(document, trace):
    pending = list(document.get('components', []))
    components = []
    while pending:
        c = pending.pop()
        components.append(c)
        pending.extend(c.get('components', []))
        if len(components) > 100_000:
            raise ValueError('Java graph component budget')
    refs = [c['bom-ref'] for c in components]
    dependencies = document.get('dependencies', [])
    if len(refs) != len(set(refs)) or len(dependencies) > 100_000:
        raise ValueError('Ambiguous Java component graph')
    by_ref = dict(zip(refs, components, strict=True))
    ids = [d['ref'] for d in dependencies]
    if len(ids) != len(set(ids)):
        raise ValueError('Duplicate Java graph node')
    graph = {d['ref']: d.get('dependsOn', []) for d in dependencies}
    wrappers = [c for c in components if c.get('type') == 'application'
                and {'name': 'aquasecurity:trivy:Type', 'value': 'pom'} in c.get('properties', [])]
    counts = Counter(c.get('name') for c in wrappers)
    rows = []
    for pom in trace:
        matches = [c for c in wrappers if c.get('name') == pom['path']]
        row = {'owner_module': pom['path'], 'owner': None, 'status': 'UNKNOWN', 'edges': [],
               'profiles': pom['profiles'], 'source_sha256': pom['sha256']}
        rows.append(row)
        children = graph.get(matches[0]['bom-ref'], []) if len(matches) == 1 else []
        if counts[pom['path']] != 1 or len(children) != 1 or children[0] not in by_ref:
            row['reason'] = 'missing_or_ambiguous_source_owner'
            continue
        ref = children[0]
        owner = coordinate(by_ref[ref])
        if not owner or ref not in graph:
            row['reason'] = 'unresolved_source_owner'
            continue
        row.update(owner=owner, status='evaluated', reason='passive_unprofiled_source_graph')
        for target in graph[ref]:
            identity = coordinate(by_ref.get(target, {}))
            edge = {'owner': owner, 'owner_module': pom['path'], 'component': identity,
                    'status': 'DIRECT' if identity else 'UNKNOWN',
                    'reason': 'trivy_resolved_source_declaration' if identity else 'unresolved_target',
                    'scope': 'unprofiled-declaration', 'build_usage_proven': False,
                    'activation': 'UNKNOWN', 'version': PackageURL.from_string(identity).version if identity else None,
                    'evidence': {'resolver': 'Trivy/' + VERSION, 'owner_ref': ref,
                                 'target_ref': target, 'source_sha256': pom['sha256']}}
            row['edges'].append(edge)
        for profile in pom['profiles']:
            for dep in profile['dependencies']:
                row['edges'].append({'owner': owner, 'owner_module': pom['path'],
                    'component': None, 'status': 'UNKNOWN', 'version': None,
                    'reason': 'build_profile_activation_not_observed',
                    'scope': dep['scope'] or 'compile', 'profile': profile['id'],
                    'declaration': dep, 'build_usage_proven': False, 'activation': 'UNKNOWN'})
    return rows


def resolve(checkout, settings):
    report = {'profile': 'java-maven-source-modules-v1', 'status': 'UNKNOWN', 'edges': [],
              'modules': [], 'graph_complete': False, 'build_usage_proven': False,
              'reference_used_as_input': False, 'source_build_executed': False}
    started = time.monotonic()
    try:
        if settings.java_maven_repository not in MIRRORS:
            raise ValueError('Unsupported service Maven repository')
        with tempfile.TemporaryDirectory(prefix='sbom-java-') as temporary:
            root = Path(temporary)
            source = root / 'source'
            trace = prepare(checkout, source)
            if not trace:
                report.update(status='not-applicable', reason='no_maven_poms')
                return report
            report['inputs'] = trace
            home = root / 'home'
            (home / '.m2').mkdir(parents=True)
            report['local_source_pom_cache'] = seed_local_poms(source, home, trace)
            # A wildcard service mirror covers repositories in local AND remote
            # POMs. No repository settings, host credentials or .m2 cache copied.
            (home / '.m2/settings.xml').write_text('<settings><mirrors><mirror><id>service</id>'
                '<mirrorOf>*</mirrorOf><url>' + settings.java_maven_repository +
                '</url></mirror></mirrors></settings>', encoding='utf-8')
            config = root / 'trivy.yaml'
            config.write_text('{}\n', encoding='utf-8')
            env = clean_environment()
            env.update(HOME=str(home), USERPROFILE=str(home), MAVEN_HOME=str(home / 'maven'),
                       XDG_CONFIG_HOME=str(home), XDG_CACHE_HOME=str(home), DOCKER_CONFIG=str(home),
                       TMPDIR=str(root), TMP=str(root), TEMP=str(root))
            version = run_command([settings.trivy_binary, 'version', '--format', 'json'],
                cwd=root, env=env, timeout=30, max_output_bytes=4096, label='Trivy version')
            if json.loads(version).get('Version') != VERSION:
                raise ValueError('Pinned Trivy version required')
            args = [settings.trivy_binary, 'fs', '--config', str(config), '--format', 'cyclonedx',
                    '--skip-db-update', '--skip-java-db-update', '--skip-version-check',
                    '--cache-dir', str(root / 'cache'), '--timeout', str(settings.java_scan_timeout) + 's']
            if settings.java_offline:
                args.append('--offline-scan')
            raw = run_command([*args, str(source)], cwd=root, env=env, timeout=settings.java_scan_timeout,
                max_output_bytes=16*1024*1024, label='Passive Java resolver',
                monitored_paths=((root, 256*1024*1024),), max_files=10_000)
            document = json.loads(raw)
            if document.get('bomFormat') != 'CycloneDX':
                raise ValueError('Invalid Java resolver output')
            report['resolver_output_sha256'] = hashlib.sha256(raw.encode()).hexdigest()
            report['modules'] = extract(document, trace)
            report['edges'] = [e for m in report['modules'] for e in m['edges']]
            report.update(status='partial' if any(m['status'] == 'UNKNOWN' for m in report['modules']) else 'evaluated',
                          resolver='Trivy/' + VERSION,
                          mode='offline' if settings.java_offline else 'public-service-mirror')
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, RecursionError):
        report.update(status='UNKNOWN', reason='java_resolver_unavailable_invalid_or_budget_exceeded')
    finally:
        report['seconds'] = round(time.monotonic()-started, 3)
        report['direct_count'] = sum(e['status'] == 'DIRECT' for e in report['edges'])
        report['unknown_count'] = None if report['status'] == 'UNKNOWN' else sum(
            e['status'] == 'UNKNOWN' for e in report['edges'])
        report['owner_coverage'] = {'evaluated': sum(m['status'] == 'evaluated' for m in report['modules']),
                                    'unknown': sum(m['status'] == 'UNKNOWN' for m in report['modules'])}
    return report
