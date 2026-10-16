"""External literal reactor plan; effective coordinates come from Maven output."""
import re
import xml.etree.ElementTree as ET

from build_java_mirror_pair import SETTINGS
from paired_java import BASE

NS = {'m': 'http://maven.apache.org/POM/4.0.0'}


def literal_modules(source):
    pending = ['.']
    result, seen = [], set()
    while pending:
        relative = pending.pop(0)
        if relative in seen or (relative != '.' and (not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', relative)
                                                     or any(p in ('.', '..') for p in relative.split('/')))):
            raise ValueError('Unsafe or duplicate literal module')
        seen.add(relative)
        directory = (source / relative).resolve()
        if not directory.is_relative_to(source.resolve()):
            raise ValueError('Module escapes source')
        root = ET.fromstring((directory / 'pom.xml').read_bytes())
        packaging = root.findtext('m:packaging', default='jar', namespaces=NS)
        if packaging not in ('jar', 'pom'):
            raise ValueError('Unsupported packaging')
        result.append({'path': relative, 'packaging': packaging})
        for element in root.findall('m:modules/m:module', NS):
            name = element.text or ''
            pending.append(name if relative == '.' else relative + '/' + name)
    if len(result) < 3:
        raise ValueError('Nontrivial reactor required')
    return result


def recipe(modules, *, profile='!all-modules'):
    if profile != '!all-modules':
        raise ValueError('Only explicitly reviewed Dropwizard profile supported')
    for row in modules:
        name = row['path']
        if (row['packaging'] not in ('jar', 'pom') or
                (name != '.' and (not re.fullmatch(r'[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*', name) or
                                  any(part in ('.', '..') for part in name.split('/'))))):
            raise ValueError('Unsafe recipe module')
    mvn = ('mvn -B -ntp -s /opt/settings.xml -P!all-modules -DskipTests '
           '-Djacoco.skip=true -Dmaven.javadoc.skip=true -Dgpg.skip=true ')
    cdx = (' -DoutputFormat=json -DoutputName=sbom -DschemaVersion=1.6 '
           '-Dcyclonedx.skipNotDeployed=false -DincludeCompileScope=true -DincludeRuntimeScope=true '
           '-DincludeTestScope=false -DincludeProvidedScope=false -DincludeSystemScope=false')
    text = (f'FROM {BASE} AS build\nENV MAVEN_OPTS="-XX:ActiveProcessorCount=2 -Xmx1536m"\n'
            'WORKDIR /src\nCOPY src/ /src/\nCOPY ReactorCollect.java /opt/ReactorCollect.java\n'
            'RUN javac -d /opt /opt/ReactorCollect.java && mkdir /reference /application\n'
            f"RUN printf '%s' '{SETTINGS}' > /opt/settings.xml\n"
            'RUN --mount=type=cache,target=/root/.m2 ' + mvn +
            'install org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeAggregateBom' + cdx +
            ' -DoutputReactorProjects=false -DoutputDirectory=/reference/aggregate\n')
    for row in modules:
        module = row['path']
        prefix = '/reference/modules/' + ('root' if module == '.' else module)
        delivered = '/application/' + ('root' if module == '.' else module)
        command = mvn + '-N -f ' + module + '/pom.xml '
        text += ('RUN --mount=type=cache,target=/root/.m2 mkdir -p ' + prefix + ' && ' + command +
                 'org.apache.maven.plugins:maven-help-plugin:3.5.1:effective-pom -Doutput=' + prefix + '/effective-pom.xml && ' + command +
                 'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree -Dscope=runtime -DoutputType=json -DoutputFile=' + prefix + '/dependency-tree.json && ' + command +
                 'org.cyclonedx:cyclonedx-maven-plugin:2.9.3:makeBom' + cdx + ' -DoutputDirectory=' + prefix)
        if row['packaging'] == 'jar':
            text += (' && ' + command + 'org.apache.maven.plugins:maven-dependency-plugin:3.8.1:copy-dependencies '
                     '-DincludeScope=runtime -DoutputDirectory=' + delivered + '/dependencies')
        text += ' && java -Xmx128m -cp /opt ReactorCollect /src/' + module + ' ' + prefix + ' ' + delivered + '\n'
    text += ('RUN ' + mvn + '-N org.apache.maven.plugins:maven-help-plugin:3.5.1:active-profiles '
             '-Doutput=/reference/active-profiles.txt && mvn --version > /reference/maven-version.txt\n'
             'FROM scratch AS runtime\nCOPY --from=build /application /application\nUSER 65532:65532\n'
             'CMD ["/not-executed-reactor-artifact-fixture"]\n')
    return text
