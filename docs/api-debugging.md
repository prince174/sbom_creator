# Debugging POST /v1/analyses

Keep the202 response `id` and query its `status_url` with the same bearer token.
Successful jobs expose the artifact list. Failed jobs expose safe `error` and
`stage`; generic `Analysis failed; output blocked` is not a root cause.

New server logs use JSON events with the same job_id: analysis.received,
analysis.queued, analysis.started, verification.started/completed when applicable,
analysis.completed or analysis.failed. Failure events include the pipeline stage
and error type, never raw exception/command output. Durations are seconds.

Enable extra input metadata with `SBOM_DEBUG_LOGGING=true` in the service's
environment and keep Uvicorn log level at info. The analysis.inputs event records
commit, repository hostname, validated image reference, platform and reference
size/component count/scope. Tokens, authorization headers, source contents and
reference contents are not logged. Default basic lifecycle events remain enabled.

For an already deployed old build, new logs are unavailable until the image is
updated. Inspect the full GET status first. Pipeline diagnostic files, when
present, live at `$SBOM_WORKSPACE/jobs/<id>/result.diagnostics/failure.json`;
completed source/image catalogs and provenance may be preserved alongside them.
The container default workspace is `/workspace`. These files may contain private
repository details; do not post complete catalogs/provenance publicly.

```sh
docker logs --since 15m <container>
docker exec <container> cat /workspace/jobs/<id>/status.json
docker exec <container> cat /workspace/jobs/<id>/result.diagnostics/failure.json
```

Commands are operator-side examples, not runtime Docker requirements. Do not
disable authentication/TLS or publish raw child-process stderr to debug failures.
This change does not restart or modify any deployed service.
