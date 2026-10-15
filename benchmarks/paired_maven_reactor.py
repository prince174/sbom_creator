"""External multi-module Maven pair with independent per-module oracle labels."""
import base64
import hashlib
import json
import re
import shutil
import xml.etree.ElementTree as ET

from http_integration import command
from paired_express import application_tree, archive_binding, export_from_image
from paired_java import BASE, verify_root
from run import ROOT, atomic_json, run_command

from sbom_creator.acquire import Settings
from sbom_creator.pipeline import analyze_local
from sbom_creator.validation import validate_cyclonedx

NS={'m':'http://maven.apache.org/POM/4.0.0'}


def main():
    project=next(p for p in json.loads((ROOT/'benchmarks/java-js-expanded-v1.json').read_bytes())['repositories'] if p['id']=='java-javalin')
    work=ROOT/'benchmarks/.work/paired-javalin-reactor-v1';out=ROOT/'benchmarks/references/paired-javalin-reactor-v1'
    if (out/'receipt.json').exists():raise FileExistsError('Immutable reactor pair exists')
    work.mkdir(parents=True,exist_ok=True);out.mkdir(parents=True,exist_ok=True);source=work/'src'
    if not source.exists():
        run_command(['git','clone','--no-hardlinks','--no-checkout',str(ROOT/'benchmarks/.work/java-javalin/src'),str(source)],work/'clone.log')
        run_command(['git','-c','core.autocrlf=false','checkout','--detach',project['commit']],work/'checkout.log',cwd=source)
    if command(['git','-C',str(source),'rev-parse','HEAD'])!=project['commit'] or command(['git','-C',str(source),'status','--porcelain']):raise ValueError('Source differs')
    root=ET.fromstring((source/'pom.xml').read_bytes());version=root.findtext('m:version',namespaces=NS)
    modules=[]
    pending = [element.text for element in root.findall('m:modules/m:module', NS)]
    seen = set()
    while pending:
        module = pending.pop(0)
        if not re.fullmatch(r'[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*', module) or module in seen:
            raise ValueError('Unsafe or repeated literal module')
        seen.add(module)
        model = ET.fromstring((source/module/'pom.xml').read_bytes())
        packaging = model.findtext('m:packaging', default='jar', namespaces=NS)
        artifact = model.findtext('m:artifactId', namespaces=NS)
        if packaging not in ('jar', 'pom') or not re.fullmatch(r'[A-Za-z0-9_.-]+', artifact):
            raise ValueError('Unsupported module output')
        modules.append({'path': module, 'packaging': packaging, 'artifact': artifact})
        pending.extend(module + '/' + element.text for element in model.findall('m:modules/m:module', NS))
    if len(modules)<2:raise ValueError('Reactor required')
    mvn='mvn -B -ntp -DskipTests -Dmaven.test.skip=true -Djacoco.skip=true -Dmaven.javadoc.skip=true -Dgpg.skip=true '
    text=f'FROM {BASE} AS build\nENV MAVEN_OPTS="-XX:ActiveProcessorCount=2 -Xmx1536m"\nWORKDIR /src\nCOPY src/ /src/\nRUN mkdir /reference /application\n'
    text+='RUN --mount=type=cache,target=/root/.m2 '+mvn+'install org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom -DoutputFormat=json -DoutputName=sbom -DschemaVersion=1.6 -DoutputReactorProjects=true -Dcyclonedx.skipNotDeployed=false -DincludeTestScope=false -DincludeProvidedScope=false -DincludeSystemScope=false && cp target/sbom.json /reference/sbom.json\n'
    for item in modules:
        module=item['path'];prefix='/reference/modules/'+module
        text+='RUN --mount=type=cache,target=/root/.m2 mkdir -p '+prefix+' && '+mvn+'-N -f '+module+'/pom.xml org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom -DoutputFormat=json -DoutputName=sbom -DschemaVersion=1.6 -Dcyclonedx.skipNotDeployed=false -DincludeTestScope=false -DincludeProvidedScope=false -DincludeSystemScope=false && cp '+module+'/target/sbom.json '+prefix+'/sbom.json && '+mvn+'-N -f '+module+'/pom.xml org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput='+prefix+'/effective-pom.xml && '+mvn+'-N -f '+module+'/pom.xml org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree -Dscope=runtime -DoutputType=json -DoutputFile='+prefix+'/dependency-tree.json'
        if item['packaging']=='jar':
            text+=' && '+mvn+'-N -f '+module+'/pom.xml org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies -DincludeScope=runtime && mkdir -p /application/'+module+' && cp '+module+'/target/'+item['artifact']+'-'+version+'.jar /application/'+module+'/ && if [ -d '+module+'/target/dependency ]; then find '+module+'/target/dependency -name \'*.jar\' -exec cp {} /application/'+module+'/ \\; ; fi'
        text+='\n'
    text+='RUN '+mvn+'-N org.apache.maven.plugins:maven-help-plugin:3.5.1:active-profiles -Doutput=/reference/active-profiles.txt && mvn --version > /reference/maven-version.txt\nFROM scratch AS runtime\nCOPY --from=build /application /application\nUSER 65532:65532\nCMD ["/not-executed-reactor-artifact-fixture"]\n'
    if (work/'Dockerfile').exists() and (work/'Dockerfile').read_text()!=text:raise ValueError('Checkpoint recipe changed')
    (work/'Dockerfile').write_text(text,encoding='utf-8');(work/'.dockerignore').write_text('**\n!Dockerfile\n!src/\n!src/**\nsrc/.git/config\nsrc/.git/hooks/\nsrc/.git/logs/\n',encoding='utf-8')
    for stage in ('build','runtime'):
        if not (work/(stage+'.id')).exists():run_command(['docker','build','--platform=linux/amd64','--target',stage,'--iidfile',str(work/(stage+'.id')),str(work)],work/(stage+'.log'),timeout=1800)
        exports=[('/application',work/(stage+'-app.tar'),True)]
        # Tar export avoids shared mutable copy-log globals.
        if stage=='build':exports.append(('/reference',work/'reference.tar',True))
        export_from_image((work/(stage+'.id')).read_text().strip(),exports,stage)
    import tarfile
    with tarfile.open(work/'reference.tar') as archive:
        for member in archive:
            name=member.name.removeprefix('reference/')
            if not member.isfile():continue
            parts=name.split('/')
            if any(p in ('','.','..') for p in parts) or member.size>16*1024*1024:raise ValueError('Unsafe reference export')
            destination=out.joinpath(*parts);destination.parent.mkdir(parents=True,exist_ok=True)
            destination.write_bytes(archive.extractfile(member).read())
    if application_tree(work/'build-app.tar')!=application_tree(work/'runtime-app.tar'):raise ValueError('Runtime payload differs')
    bom=json.loads((out/'sbom.json').read_bytes());validate_cyclonedx(bom)
    labels=[]
    for item in modules:
        directory=out/'modules'/item['path'];document=json.loads((directory/'sbom.json').read_bytes());validate_cyclonedx(document)
        label=verify_root(document,json.loads((directory/'dependency-tree.json').read_bytes()),(directory/'effective-pom.xml').read_bytes())
        labels.append(dict(item,**label,image_prefix='/application/'+item['path']+'/' if item['packaging']=='jar' else None))
    atomic_json(out/'module-labels.json',labels)
    image=(work/'runtime.id').read_text().strip();archive=work/'image.tar'
    if not archive.exists():run_command(['docker','image','save','-o',str(archive),image],work/'save.log',timeout=300)
    binding=archive_binding(archive,image);analysis=work/'analysis'
    failure_path = work/'scan-budget-failure.json'
    if failure_path.exists():
        analysis_status = json.loads(failure_path.read_bytes())
        if analysis_status != {'stage': 'image_scan', 'type': 'RuntimeError', 'reason': 'Syft exceeded output limit', 'max_sbom_bytes': 67108864, 'runtime_limits_changed': False}:
            raise ValueError('Unexpected saved analysis failure')
        analysis_status['status'] = 'FAILED_OUTPUT_BUDGET'
        shutil.copyfile(failure_path, out/'service-analysis-failure.json')
    else:
        if not (analysis/'summary.json').exists():
            analyze_local(source,'docker.io/sbom-creator-benchmark/paired-javalin-reactor:v1',analysis,Settings(syft_binary=str(ROOT/'.tools/syft/syft.exe'),registry_hosts=('docker.io',),image_archive=str(archive)))
        catalog=json.loads((analysis/'image.syft.json').read_bytes())
        if 'sha256:'+hashlib.sha256(base64.b64decode(catalog['source']['metadata']['config'],validate=True)).hexdigest()!=binding['config_digest']:
            raise ValueError('Scanned config differs')
        for view in ('final','os','full'):
            validate_cyclonedx(json.loads((analysis/(view+'.cdx.json')).read_bytes()))
        analysis_status = {'status': 'SUCCESS', 'three_views_valid': True}
    shutil.copyfile(work/'Dockerfile',out/'Dockerfile')
    atomic_json(out/'application-tree.json',application_tree(work/'runtime-app.tar'))
    atomic_json(out/'receipt.json',{'project':project['id'],'commit':project['commit'],'runtime_kind':'maven-reactor-artifacts','image_binding':binding,'artifact_tree_equal':True,'reference_only_for_evaluation':True,'analysis_status':analysis_status,'module_count':len(labels),'module_direct_edges':sum(len(x['direct']) for x in labels),'reference_hashes':{p.relative_to(out).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in out.rglob('*') if p.is_file() and p.name!='receipt.json'},'limitation':'Separate module root labels validated; aggregate root is not interpreted as direct dependencies; POM-only modules not shipped; no runtime direct classification inferred.'})
    print(json.dumps({'paired':True,'modules':len(labels),'direct_edges':sum(len(x['direct']) for x in labels)}))


if __name__=='__main__':main()
