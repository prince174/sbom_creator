# R48: reject mismatched Go payload rescan identity

Date: 2026-10-15. Acquisition verification only; no runtime or classifier change.

Hypothesis: a content rescan must reject a different expected image configuration
before returning bytes, even when the requested file exists and is readable.
The existing R45 positive archive checks already verify matching identities.

Ran real Syft 1.51.1 scans of the paired Hey and Lazygit archives, passing an
incorrect all-zero SHA256 configuration digest. Both raised exactly
`Rescanned image differs`; neither returned a payload. This exercises the real
scan and comparison, not a mocked scanner. [Result](go-payload-identity-v1.json).

Reproduce with the existing paired archives:

```powershell
.venv/Scripts/python.exe -X utf8 benchmarks/check_go_payload_identity.py
.venv/Scripts/python.exe -X utf8 -m pytest tests/test_scanner.py -q
.venv/Scripts/ruff.exe check benchmarks/check_go_payload_identity.py
```

The targeted scanner suite also covers registry digest mismatch and accepted
parent index digests using mocked scan metadata. Those unit checks do not prove
live authenticated registry operation or mutable-tag race handling.

[Official Syft source documentation](https://github.com/anchore/syft/wiki/supported-sources)
documents explicit registry access without a container runtime. The current
experimental bridge still hardcodes the archive backend; this run does not add
registry support. Next stage requires a separate controlled registry fixture
and credential isolation before a production integration decision. Direct
dependency accuracy remains unmeasured in this acquisition experiment.
