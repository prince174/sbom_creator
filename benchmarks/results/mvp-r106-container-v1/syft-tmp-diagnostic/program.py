
import json,os,pathlib,shutil,signal,subprocess,tempfile,time
from sbom_creator import scanner
from sbom_creator.acquire import clean_environment
out=pathlib.Path('/workspace')
with tempfile.TemporaryDirectory(prefix='sbom-syft-') as directory:
    root=pathlib.Path(directory)
    cfg=scanner.IMAGE_CONFIG
    for suffix in ('jar','war','ear','zip','hpi','jpi','nar','jmod'):
        cfg=cfg.replace('      - "**/*.'+suffix+'"\n','')
    config=root/'syft.yaml';config.write_text(scanner.TRUSTED_CONFIG+cfg)
    (out/'syft-config.yaml').write_text(config.read_text())
    environment=clean_environment();environment.update(HOME=directory,USERPROFILE=directory,XDG_CONFIG_HOME=directory,XDG_CACHE_HOME=directory,SYFT_CHECK_FOR_APP_UPDATE='false',TMPDIR=directory,TMP=directory,TEMP=directory,DOCKER_CONFIG=directory)
    command=['syft','scan','docker-archive:/inputs/image.tar','--platform','linux/amd64','--override-default-catalogers','image','--scope','squashed','-o','syft-json','--config',str(config)]
    started=time.monotonic();samples=[];guard=None
    with (out/'stdout.json').open('wb') as stdout,(out/'stderr.log').open('wb') as stderr:
        process=subprocess.Popen(command,env=environment,cwd=root,stdout=stdout,stderr=stderr,start_new_session=True)
        while process.poll() is None:
            usage=shutil.disk_usage('/tmp');samples.append({'elapsed_seconds':round(time.monotonic()-started,3),'tmp_used_bytes':usage.used,'tmp_free_bytes':usage.free})
            if (out/'stdout.json').stat().st_size>64*1024**2 or (out/'stderr.log').stat().st_size>4*1024**2:guard='output-budget'
            if time.monotonic()-started>240:guard='timeout'
            if guard:os.killpg(process.pid,signal.SIGKILL);break
            time.sleep(.2)
        exit_code=process.wait()
    stderr=(out/'stderr.log').read_text(errors='replace')[-4096:]
    report={'exit_code':exit_code,'guard':guard,'elapsed_seconds':round(time.monotonic()-started,3),'command':command,'tmpfs_bytes':shutil.disk_usage('/tmp').total,'min_observed_free_bytes':min(x['tmp_free_bytes'] for x in samples),'controlled_fixture_stderr_tail':stderr,'samples':samples,'reference_accessed':False,'test_boundary':'Pinned Syft only; no classifier, Java peer or reference input'}
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps({k:v for k,v in report.items() if k!='samples'},indent=2))
