"""Pin a larger, stratified Java/JS corpus before tuning on it."""
import hashlib
import json
import subprocess
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from run import ROOT, atomic_json

CANDIDATES = [
 ('java-commons-configuration','Java','apache/commons-configuration','refs/tags/rel/commons-configuration-2.11.0','development',['optional','exclusions','many-direct']),
 ('java-spring-petclinic','Java','spring-projects/spring-petclinic','HEAD','development',['spring-boot-app','profiles','dependency-management']),
 ('java-petclinic-rest','Java','spring-petclinic/spring-petclinic-rest','HEAD','holdout',['spring-boot-rest','profiles','database-drivers']),
 ('java-dropwizard','Java','dropwizard/dropwizard','HEAD','holdout',['maven-reactor','bom','modules']),
 ('java-vertx-web','Java','vert-x3/vertx-web','HEAD','development',['maven-reactor','modules','optional']),
 ('java-jib','Java','GoogleContainerTools/jib','HEAD','development',['gradle-multimodule','plugins']),
 ('java-okhttp','Java','square/okhttp','HEAD','holdout',['gradle-kotlin','multiplatform','modules']),
 ('java-resilience4j','Java','resilience4j/resilience4j','HEAD','holdout',['gradle-multimodule','optional-integrations']),
 ('java-javalin','Java','javalin/javalin','HEAD','development',['maven-reactor','kotlin-java','profiles']),
 ('java-petclinic-microservices','Java','spring-petclinic/spring-petclinic-microservices','HEAD','development',['multiple-services','spring-bom','profiles']),
 ('javascript-pino','JavaScript','pinojs/pino','refs/tags/v9.6.0','holdout',['many-direct','transport','dev-runtime']),
 ('javascript-http-server','JavaScript','http-party/http-server','HEAD','development',['cli-app','many-direct']),
 ('javascript-fastify-cli','JavaScript','fastify/fastify-cli','HEAD','development',['cli-app','plugins','dev-runtime']),
 ('javascript-nest-starter','JavaScript','nestjs/typescript-starter','HEAD','holdout',['typescript-build','peer','application']),
 ('javascript-nest','JavaScript','nestjs/nest','HEAD','development',['monorepo','peer','typescript-build']),
 ('javascript-eslint','JavaScript','eslint/eslint','HEAD','holdout',['workspaces','cli-app','optional']),
 ('javascript-vite','JavaScript','vitejs/vite','HEAD','development',['pnpm-workspace','typescript-build','native-optional']),
 ('javascript-verdaccio','JavaScript','verdaccio/verdaccio','HEAD','holdout',['monorepo','plugins','application']),
 ('javascript-sveltekit','JavaScript','sveltejs/kit','HEAD','development',['pnpm-workspace','peer','application-build']),
 ('javascript-next','JavaScript','vercel/next.js','HEAD','development',['pnpm-workspace','native-optional','framework-build']),
]


def main():
    output = ROOT / 'benchmarks/java-js-expanded-v1.json'
    if output.exists():
        raise FileExistsError('Frozen corpus already exists')
    rows = []
    for project, language, repository, ref, split, challenges in CANDIDATES:
        url = 'https://github.com/' + repository + '.git'
        remote = subprocess.check_output(['git','ls-remote',url,ref,ref+'^{}'],text=True,timeout=40)
        refs = dict(reversed(line.split()) for line in remote.splitlines())
        commit = refs.get(ref+'^{}',refs.get(ref))
        if not commit or len(commit)!=40:
            raise ValueError('Unresolved '+project)
        row = {'id':project,'language':language,'repository_url':url,'release_ref':ref,'commit':commit,
               'partition':split,'planned_challenges':challenges,'status':'PINNED_NOT_BUILT','manifests':{}}
        snapshot = ROOT / 'benchmarks/corpus-inputs/expanded-v1' / project
        snapshot.mkdir(parents=True,exist_ok=True)
        names = ['pom.xml','build.gradle','build.gradle.kts','settings.gradle','settings.gradle.kts'] if language=='Java' else ['package.json','pnpm-workspace.yaml']
        for name in names:
            source = 'https://raw.githubusercontent.com/'+repository+'/'+commit+'/'+name
            try:
                with urllib.request.urlopen(source,timeout=20) as response:
                    raw=response.read(2*1024*1024+1)
            except urllib.error.HTTPError as error:
                if error.code==404:continue
                raise
            if len(raw)>2*1024*1024:raise ValueError('Manifest budget exceeded')
            (snapshot/name).write_bytes(raw)
            row['manifests'][name]={'source':source,'sha256':hashlib.sha256(raw).hexdigest()}
        if 'pom.xml' in row['manifests']:
            root=ET.fromstring((snapshot/'pom.xml').read_bytes());ns={'m':'http://maven.apache.org/POM/4.0.0'}
            row['declared_root_modules']=[m.text for m in root.findall('m:modules/m:module',ns)]
            row['declared_root_dependency_count']=len(root.findall('m:dependencies/m:dependency',ns))
            artifact=root.findtext('m:artifactId',namespaces=ns)
            version=root.findtext('m:version',namespaces=ns)
            group=root.findtext('m:groupId',namespaces=ns) or root.findtext('m:parent/m:groupId',namespaces=ns)
            if group and artifact:row['expected_package']=group+':'+artifact
            if version:row['expected_version']=version
        if 'package.json' in row['manifests']:
            package=json.loads((snapshot/'package.json').read_bytes())
            row.update(declared_root_dependency_count=len(package.get('dependencies',{})),
                       declared_workspaces=package.get('workspaces'),package_manager=package.get('packageManager'),
                       scripts=package.get('scripts',{}),engines=package.get('engines',{}))
        rows.append(row)
        print(project,commit,flush=True)
    files=['src/sbom_creator/npm_direct.py','src/sbom_creator/core.py','src/sbom_creator/pipeline.py','benchmarks/maven_optional_fingerprint.py']
    atomic_json(output,{'schema_version':1,'date':'2026-10-15','target_primary_pairs_per_language':20,
               'repositories':rows,'candidate_freeze':{f:hashlib.sha256((ROOT/f).read_bytes()).hexdigest() for f in files},
               'protocol':'Fixed expansion, 6 development + 4 holdout per language. Holdout accuracy is not used to change rules. Existing20 primary pairs unchanged; DBCP extra control remains separate. Planned challenges require verification in actual builds. All failures and UNKNOWN retained; no empty-example accuracy.'})


if __name__=='__main__':
    main()
