import json

from paired_java import JRE, recipe
from run import ROOT


def test_existing_library_recipe_stays_identical():
    manifest=json.loads((ROOT/'benchmarks/manifest.json').read_bytes())
    project=next(r for r in manifest['repositories'] if r['id']=='java-commons-compress')
    assert recipe(project)==(ROOT/'benchmarks/references/paired-commons-compress-v1/Dockerfile').read_text()


def test_boot_image_has_jre_and_single_boot_jar_layout():
    text=recipe({'id':'java-app','expected_package':'example:app','expected_version':'1.0',
                 'runtime_kind':'spring-boot-jar'})
    runtime=text.split(' AS runtime\n',1)[1]
    assert 'FROM '+JRE+' AS runtime' in text
    assert 'CMD ["java", "-jar", "/application/app-1.0.jar"]' in runtime
    assert 'USER 65532:65532' in runtime
    assert 'target/dependency ]; then find' not in text
    assert '/reference' not in runtime
