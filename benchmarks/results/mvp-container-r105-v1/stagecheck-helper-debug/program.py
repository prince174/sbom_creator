
import json,pathlib,tempfile,traceback
from sbom_creator.acquire import Settings
from sbom_creator.image_java.runtime import peer,corroborate
out=pathlib.Path('/workspace')
settings=Settings(trivy_cache_dir='/workspace/trivy-cache',image_archive='/inputs/image.tar')
with tempfile.TemporaryDirectory(dir=out) as tmp:
    try:
        p,t=peer(pathlib.Path('/inputs/image.tar'),settings,tmp)
        (out/'peer.cdx.json').write_text(json.dumps(p))
        (out/'peer-tool.json').write_text(json.dumps(t))
        print('peer passed',flush=True)
    except Exception as e:
        (out/'failure.json').write_text(json.dumps({'stage':'peer','type':type(e).__name__,'fixture_error':str(e)}))
        traceback.print_exc();raise
    try:
        image=json.loads(pathlib.Path('/inputs/image.syft.json').read_text())
        adapted,physical,envelope,audit=corroborate(image,pathlib.Path('/inputs/image.tar'),p,temporary=tmp)
        (out/'audit.json').write_text(json.dumps(audit))
        print('corroborate passed',flush=True)
    except Exception as e:
        (out/'failure.json').write_text(json.dumps({'stage':'corroborate','type':type(e).__name__,'fixture_error':str(e)}))
        traceback.print_exc();raise
