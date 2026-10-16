
import json,os,pathlib,subprocess,time,urllib.error,urllib.request
root=pathlib.Path('/tmp/http-smoke');root.mkdir()
env=dict(os.environ,SBOM_WORKSPACE=str(root/'workspace'),SBOM_API_TOKEN='synthetic-container-smoke-only',SBOM_REGISTRY_HOSTS='docker.io',SBOM_PORT='8080')
with (root/'server.log').open('wb') as log:
    server=subprocess.Popen(['sbom-creator-service'],env=env,stdout=log,stderr=subprocess.STDOUT)
    try:
        for _ in range(100):
            try:
                health=json.load(urllib.request.urlopen('http://127.0.0.1:8080/health',timeout=1));break
            except (urllib.error.URLError,TimeoutError):
                if server.poll() is not None:raise RuntimeError('Service exited during startup')
                time.sleep(.1)
        else:raise RuntimeError('Service did not become healthy')
        def request(body,authorized=True):
            headers={'Content-Type':'application/json'}
            if authorized:headers['Authorization']='Bearer synthetic-container-smoke-only'
            query=urllib.request.Request('http://127.0.0.1:8080/v1/analyses',data=json.dumps(body).encode(),headers=headers)
            try:
                with urllib.request.urlopen(query,timeout=2) as response:return response.status,json.load(response)
            except urllib.error.HTTPError as error:return error.code,json.load(error)
        image={'image':'blocked.example/app@sha256:'+'0'*64}
        unauth=request(image,False);imageonly=request(image)
        paired=request(dict(image,repository_url='https://example.com/org/repo.git'))
        assert health['status']=='ok'
        assert unauth[0]==401
        assert imageonly==(422,{'detail':'Invalid or unauthorized repository/commit/image'})
        assert paired[0]==422 and isinstance(paired[1]['detail'],list)
        assert not list((root/'workspace/jobs').iterdir())
        print(json.dumps({'status':'passed','uid':os.geteuid(),'health':health,'unauthenticated':unauth,'image_only_reaches_registry_authorization':imageonly,'incomplete_source_pair_status':paired[0],'jobs_created':0,'test_boundary':'HTTP/auth/request model; actual image analysis covered by separate installed pipeline smoke'}))
    finally:
        server.terminate();server.wait(timeout=10)
